#![allow(unsafe_code)]
//! Linux PID 1 setup, read-only rootfs + overlay switch, signal forwarding, and zombie reaper.

use std::ffi::CString;
use std::fs::{self, Permissions};
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, ExitCode};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use crate::plan::{BootConfig, ETC_OVERLAY_OPTIONS, REQUIRED_MODULES, WRITABLE_BIND_MOUNTS};

const DEVICE_WAIT_TIMEOUT: Duration = Duration::from_secs(5);
const DEVICE_POLL_INTERVAL: Duration = Duration::from_millis(50);
const SHUTDOWN_GRACE_PERIOD: Duration = Duration::from_secs(3);
const SHUTDOWN_POLL_INTERVAL: Duration = Duration::from_millis(20);

const RW_SUBDIRS: &[(&str, u32)] = &[
    ("/mnt/disk/rw/etc-upper", 0o755),
    ("/mnt/disk/rw/etc-work", 0o755),
    ("/mnt/disk/rw/containers", 0o755),
    ("/mnt/disk/rw/workspace", 0o755),
    ("/mnt/disk/rw/tmp", 0o1777),
    ("/mnt/disk/rw/var-tmp", 0o1777),
    ("/mnt/disk/rw/root", 0o700),
];

static SHUTDOWN_REQUESTED: AtomicBool = AtomicBool::new(false);

extern "C" fn handle_shutdown_signal(_sig: libc::c_int) {
    SHUTDOWN_REQUESTED.store(true, Ordering::Release);
}

/// Runs guest initialization, supervises the agent until exit, and powers off when PID 1.
pub(crate) fn run() -> ExitCode {
    // SAFETY: `getpid` is always safe to call and requires no pointers or shared state.
    let is_pid1 = unsafe { libc::getpid() } == 1;
    if is_pid1 {
        if let Err(err) = set_process_name(b"tiny-init\0") {
            eprintln!("[tiny-init] warning: prctl(PR_SET_NAME) failed: {err}");
        }
    }

    let code = match run_init() {
        Ok(status) => status,
        Err(err) => {
            eprintln!("[tiny-init] fatal error: {err}");
            1
        }
    };

    if is_pid1 {
        eprintln!("[tiny-init] shutting down guest (exit code {code})");
        power_off();
    }

    ExitCode::from(u8::try_from(code).unwrap_or(1))
}

fn run_init() -> io::Result<i32> {
    early_initramfs_setup()?;

    let cmdline = fs::read_to_string("/proc/cmdline")?;
    let config = BootConfig::from_cmdline(&cmdline);

    if let Some(root_dev) = config.root_device.as_deref() {
        switch_to_ro_root_with_overlay(root_dev)?;
    }

    install_signal_handlers()?;

    let child = Command::new(&config.agent_path)
        .env("PATH", "/bin:/sbin:/usr/bin:/usr/sbin")
        .process_group(0)
        .spawn()
        .map_err(|err| {
            io::Error::new(
                err.kind(),
                format!("failed to spawn agent '{}': {err}", config.agent_path),
            )
        })?;

    let agent_pid = libc::pid_t::try_from(child.id())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "agent pid overflows pid_t"))?;
    // Dropping `Child` on Unix does not kill or wait on the process; `reap_until_agent_exits` owns reaping.
    drop(child);

    Ok(reap_until_agent_exits(agent_pid))
}

fn early_initramfs_setup() -> io::Result<()> {
    for dir in ["/proc", "/sys", "/dev", "/run"] {
        fs::create_dir_all(dir)?;
    }

    const EARLY_MOUNTS: &[(&str, &str, &str)] = &[
        ("proc", "/proc", "proc"),
        ("sysfs", "/sys", "sysfs"),
        ("devtmpfs", "/dev", "devtmpfs"),
        ("tmpfs", "/run", "tmpfs"),
    ];
    for &(src, target, fstype) in EARLY_MOUNTS {
        mount_raw(Some(src), target, Some(fstype), 0, None, true)?;
    }

    if Path::new("/sbin/modprobe").exists() {
        for module in REQUIRED_MODULES {
            if let Err(err) = Command::new("/sbin/modprobe").args(["-q", module]).status() {
                eprintln!("[tiny-init] warning: modprobe -q {module} failed to spawn: {err}");
            }
        }
    }

    populate_virtio_ports(Path::new("/sys"), Path::new("/dev"))?;
    Ok(())
}

fn switch_to_ro_root_with_overlay(root_dev: &str) -> io::Result<()> {
    wait_for_device(Path::new(root_dev), DEVICE_WAIT_TIMEOUT, DEVICE_POLL_INTERVAL)?;

    fs::create_dir_all("/mnt/disk")?;
    mount_raw(
        Some(root_dev),
        "/mnt/disk",
        Some("ext4"),
        libc::MS_NOATIME,
        None,
        false,
    )?;

    fs::create_dir_all("/mnt/disk/rw")?;
    fs::set_permissions("/mnt/disk/rw", Permissions::from_mode(0o755))?;
    for &(dir, mode) in RW_SUBDIRS {
        fs::create_dir_all(dir)?;
        fs::set_permissions(dir, Permissions::from_mode(mode))?;
    }

    fs::create_dir_all("/newroot")?;
    mount_raw(
        Some("/mnt/disk/rootfs"),
        "/newroot",
        None,
        libc::MS_BIND,
        None,
        false,
    )?;
    mount_raw(
        None,
        "/newroot",
        None,
        libc::MS_BIND | libc::MS_REMOUNT | libc::MS_RDONLY,
        None,
        false,
    )?;

    mount_raw(
        Some("overlay"),
        "/newroot/etc",
        Some("overlay"),
        0,
        Some(ETC_OVERLAY_OPTIONS),
        false,
    )?;

    for &(src, target) in WRITABLE_BIND_MOUNTS {
        mount_raw(Some(src), target, None, libc::MS_BIND, None, false)?;
    }

    const NEWROOT_VIRTUAL_MOUNTS: &[(&str, &str, &str)] = &[
        ("tmpfs", "/newroot/run", "tmpfs"),
        ("proc", "/newroot/proc", "proc"),
        ("sysfs", "/newroot/sys", "sysfs"),
        ("devtmpfs", "/newroot/dev", "devtmpfs"),
    ];
    for &(src, target, fstype) in NEWROOT_VIRTUAL_MOUNTS {
        mount_raw(Some(src), target, Some(fstype), 0, None, false)?;
    }

    fs::create_dir_all("/newroot/dev/pts")?;
    mount_raw(
        Some("devpts"),
        "/newroot/dev/pts",
        Some("devpts"),
        0,
        None,
        false,
    )?;

    populate_virtio_ports(Path::new("/newroot/sys"), Path::new("/newroot/dev"))?;

    for old_mount in ["/mnt/disk", "/run", "/proc", "/sys", "/dev"] {
        umount_detach(old_mount)?;
    }

    std::env::set_current_dir("/newroot")?;
    chroot_dot()?;
    std::env::set_current_dir("/")?;
    Ok(())
}

fn wait_for_device(dev_path: &Path, timeout: Duration, interval: Duration) -> io::Result<()> {
    if dev_path.exists() {
        return Ok(());
    }

    let deadline = Instant::now() + timeout;
    let mut ran_mdev = false;
    loop {
        if !ran_mdev {
            ran_mdev = true;
            if Path::new("/sbin/mdev").exists() {
                let _ = Command::new("/sbin/mdev").arg("-s").status();
                if dev_path.exists() {
                    return Ok(());
                }
            }
        }
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!(
                    "root device '{}' did not appear within {:?}",
                    dev_path.display(),
                    timeout
                ),
            ));
        }
        thread::sleep(interval);
        if dev_path.exists() {
            return Ok(());
        }
    }
}

fn populate_virtio_ports(sys_root: &Path, dev_root: &Path) -> io::Result<()> {
    let class_dir = sys_root.join("class/virtio-ports");
    let entries = match fs::read_dir(&class_dir) {
        Ok(entries) => entries,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(err),
    };

    let ports_dir = dev_root.join("virtio-ports");
    fs::create_dir_all(&ports_dir)?;

    for entry in entries {
        let entry = entry?;
        let file_name = entry.file_name();
        let Some(vport_name) = file_name.to_str() else {
            continue;
        };
        if !vport_name.starts_with("vport") {
            continue;
        }

        let port_name = match fs::read_to_string(entry.path().join("name")) {
            Ok(raw) => raw.trim().to_owned(),
            Err(err) if err.kind() == io::ErrorKind::NotFound => continue,
            Err(err) => return Err(err),
        };
        if port_name.is_empty()
            || port_name.contains('/')
            || port_name.contains('\0')
            || port_name == "."
            || port_name == ".."
        {
            continue;
        }
        if !dev_root.join(vport_name).exists() {
            continue;
        }

        let link_path = ports_dir.join(&port_name);
        if fs::symlink_metadata(&link_path).is_ok() {
            fs::remove_file(&link_path)?;
        }
        std::os::unix::fs::symlink(format!("../{vport_name}"), &link_path)?;
    }

    Ok(())
}

fn install_signal_handlers() -> io::Result<()> {
    SHUTDOWN_REQUESTED.store(false, Ordering::Release);

    // SAFETY: Zero-initializes all fields (including architecture-specific `sa_restorer`/padding),
    // sets `sa_sigaction` to an async-signal-safe `extern "C"` handler with `sa_flags = 0` (no
    // `SA_RESTART`) so blocking `waitpid` returns `EINTR`, and clears `sa_mask` via `sigemptyset`.
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction =
            (handle_shutdown_signal as extern "C" fn(libc::c_int)) as *const () as libc::sighandler_t;
        sa.sa_flags = 0;
        if libc::sigemptyset(&mut sa.sa_mask) != 0 {
            return Err(io::Error::last_os_error());
        }
        if libc::sigaction(libc::SIGTERM, &sa, std::ptr::null_mut()) != 0 {
            return Err(io::Error::last_os_error());
        }
        if libc::sigaction(libc::SIGINT, &sa, std::ptr::null_mut()) != 0 {
            return Err(io::Error::last_os_error());
        }
    }

    Ok(())
}

/// Reaps all exited children and reparented orphans with 0% idle CPU until `agent_pid` exits.
///
/// Forwards `SIGTERM` (then `SIGKILL` after [`SHUTDOWN_GRACE_PERIOD`]) to the agent's process
/// group when a shutdown signal arrives, and drains any remaining zombies before returning.
pub(crate) fn reap_until_agent_exits(agent_pid: libc::pid_t) -> i32 {
    let mut shutdown_deadline: Option<Instant> = None;
    let mut sigkill_sent = false;
    let mut agent_exit_code: Option<i32> = None;

    while agent_exit_code.is_none() {
        if SHUTDOWN_REQUESTED.load(Ordering::Acquire) && shutdown_deadline.is_none() {
            send_signal_to_group(agent_pid, libc::SIGTERM);
            shutdown_deadline = Some(Instant::now() + SHUTDOWN_GRACE_PERIOD);
        }

        if let Some(deadline) = shutdown_deadline {
            let mut status: libc::c_int = 0;
            // SAFETY: `waitpid(-1, &mut status, WNOHANG)` is valid to reap any exited child.
            let pid = unsafe { libc::waitpid(-1, &mut status, libc::WNOHANG) };
            if pid > 0 {
                if pid == agent_pid {
                    agent_exit_code = Some(wait_status_to_exit_code(status));
                }
                continue;
            }
            if pid == -1 {
                let err = io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                if err.raw_os_error() == Some(libc::ECHILD) {
                    break;
                }
                eprintln!("[tiny-init] waitpid(WNOHANG) failed during shutdown: {err}");
                break;
            }
            if !sigkill_sent && Instant::now() >= deadline {
                send_signal_to_group(agent_pid, libc::SIGKILL);
                sigkill_sent = true;
                continue;
            }
            thread::sleep(SHUTDOWN_POLL_INTERVAL);
        } else {
            let mut status: libc::c_int = 0;
            // SAFETY: `waitpid(-1, &mut status, 0)` blocks at 0% CPU until any child exits or
            // a signal handler registered without `SA_RESTART` interrupts it with `EINTR`.
            let pid = unsafe { libc::waitpid(-1, &mut status, 0) };
            if pid > 0 {
                if pid == agent_pid {
                    agent_exit_code = Some(wait_status_to_exit_code(status));
                }
                continue;
            }
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            if err.raw_os_error() == Some(libc::ECHILD) {
                break;
            }
            eprintln!("[tiny-init] waitpid failed: {err}");
            break;
        }
    }

    drain_zombies();
    agent_exit_code.unwrap_or(1)
}

fn send_signal_to_group(agent_pid: libc::pid_t, sig: libc::c_int) {
    // SAFETY: `kill(-agent_pid, sig)` targets the agent process group (`pgid == agent_pid`),
    // falling back to `agent_pid` directly if the process group does not exist (`ESRCH`).
    unsafe {
        if libc::kill(-agent_pid, sig) != 0 {
            let _ = libc::kill(agent_pid, sig);
        }
    }
}

fn drain_zombies() {
    loop {
        let mut status: libc::c_int = 0;
        // SAFETY: `waitpid(-1, &mut status, WNOHANG)` reaps exited zombies without blocking.
        let pid = unsafe { libc::waitpid(-1, &mut status, libc::WNOHANG) };
        if pid > 0 {
            continue;
        }
        if pid == 0 {
            break;
        }
        if io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
            break;
        }
    }
}

fn wait_status_to_exit_code(status: libc::c_int) -> i32 {
    if libc::WIFEXITED(status) {
        libc::WEXITSTATUS(status)
    } else if libc::WIFSIGNALED(status) {
        128 + libc::WTERMSIG(status)
    } else {
        1
    }
}

fn mount_raw(
    source: Option<&str>,
    target: &str,
    fstype: Option<&str>,
    flags: libc::c_ulong,
    data: Option<&str>,
    tolerate_ebusy: bool,
) -> io::Result<()> {
    let source_c = source.map(to_cstring).transpose()?;
    let target_c = to_cstring(target)?;
    let fstype_c = fstype.map(to_cstring).transpose()?;
    let data_c = data.map(to_cstring).transpose()?;

    let src_ptr = source_c.as_ref().map_or(std::ptr::null(), |s| s.as_ptr());
    let fstype_ptr = fstype_c.as_ref().map_or(std::ptr::null(), |s| s.as_ptr());
    let data_ptr = data_c
        .as_ref()
        .map_or(std::ptr::null(), |s| s.as_ptr().cast::<libc::c_void>());

    // SAFETY: All non-null pointers point to live NUL-terminated `CString` buffers owned by this
    // stack frame for the entire `libc::mount` call.
    let rc = unsafe { libc::mount(src_ptr, target_c.as_ptr(), fstype_ptr, flags, data_ptr) };
    if rc == 0 {
        return Ok(());
    }
    let err = io::Error::last_os_error();
    if tolerate_ebusy && err.raw_os_error() == Some(libc::EBUSY) {
        return Ok(());
    }
    Err(io::Error::new(
        err.kind(),
        format!(
            "mount(source={source:?}, target='{target}', fstype={fstype:?}, flags={flags:#x}) failed: {err}"
        ),
    ))
}

fn umount_detach(target: &str) -> io::Result<()> {
    let target_c = to_cstring(target)?;
    // SAFETY: `target_c` is a live NUL-terminated `CString` passed to `umount2`.
    let rc = unsafe { libc::umount2(target_c.as_ptr(), libc::MNT_DETACH) };
    if rc == 0 {
        return Ok(());
    }
    let err = io::Error::last_os_error();
    match err.raw_os_error() {
        Some(libc::EINVAL | libc::ENOENT) => Ok(()),
        _ => Err(io::Error::new(
            err.kind(),
            format!("umount2('{target}', MNT_DETACH) failed: {err}"),
        )),
    }
}

fn chroot_dot() -> io::Result<()> {
    let dot = to_cstring(".")?;
    // SAFETY: `dot` is a live NUL-terminated `CString` passed to `chroot`.
    if unsafe { libc::chroot(dot.as_ptr()) } != 0 {
        let err = io::Error::last_os_error();
        return Err(io::Error::new(
            err.kind(),
            format!("chroot(\".\") failed: {err}"),
        ));
    }
    Ok(())
}

fn power_off() {
    // SAFETY: `sync` and `reboot(LINUX_REBOOT_CMD_POWER_OFF)` cleanly flush disk buffers and halt
    // the guest kernel without panicking PID 1.
    unsafe {
        libc::sync();
        if libc::reboot(libc::LINUX_REBOOT_CMD_POWER_OFF) != 0 {
            let err = io::Error::last_os_error();
            eprintln!("[tiny-init] reboot(POWER_OFF) failed: {err}");
        }
    }
}

fn to_cstring(value: &str) -> io::Result<CString> {
    CString::new(value).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("path or mount option contains interior NUL byte: {value:?}"),
        )
    })
}

fn set_process_name(name_with_nul: &[u8]) -> io::Result<()> {
    if name_with_nul.last() != Some(&0) || name_with_nul.len() > 16 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "process name must be NUL-terminated and at most 16 bytes",
        ));
    }

    // SAFETY: `name_with_nul` is verified to end with NUL and fit within Linux's 16-byte `TASK_COMM_LEN`.
    let rc = unsafe {
        libc::prctl(
            libc::PR_SET_NAME,
            name_with_nul.as_ptr() as libc::c_ulong,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn sleep_ms_async_signal_safe(ms: u32) {
        // SAFETY: Zero-initialized `timespec` handles optional time64 padding fields across musl/glibc.
        unsafe {
            let mut req: libc::timespec = std::mem::zeroed();
            req.tv_sec = (ms / 1000) as _;
            req.tv_nsec = ((ms % 1000) as libc::c_long) * 1_000_000;
            let mut rem: libc::timespec = std::mem::zeroed();
            while libc::nanosleep(&req, &mut rem) == -1 {
                if io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                    req = rem;
                } else {
                    break;
                }
            }
        }
    }

    #[test]
    fn subreaper_reaps_reparented_grandchild_with_zero_trailing_zombies() {
        // Isolate `PR_SET_CHILD_SUBREAPER` in a dedicated forked subprocess so test runner threads never interfere.
        // SAFETY: `fork`, `prctl`, `waitpid`, `nanosleep`, and `_exit` are invoked with valid
        // arguments; forked children use only raw libc syscalls and `_exit`.
        let subreaper_pid = unsafe { libc::fork() };
        assert!(subreaper_pid >= 0, "fork subreaper failed");

        if subreaper_pid == 0 {
            let prctl_rc = unsafe {
                libc::prctl(
                    libc::PR_SET_CHILD_SUBREAPER,
                    1 as libc::c_ulong,
                    0 as libc::c_ulong,
                    0 as libc::c_ulong,
                    0 as libc::c_ulong,
                )
            };
            if prctl_rc != 0 {
                unsafe { libc::_exit(10) };
            }

            let intermediate = unsafe { libc::fork() };
            if intermediate < 0 {
                unsafe { libc::_exit(11) };
            }
            if intermediate == 0 {
                let grandchild = unsafe { libc::fork() };
                if grandchild < 0 {
                    unsafe { libc::_exit(20) };
                }
                if grandchild == 0 {
                    sleep_ms_async_signal_safe(100);
                    unsafe { libc::_exit(0) };
                }
                // Intermediate exits immediately so grandchild reparents to `subreaper_pid`.
                unsafe { libc::_exit(0) };
            }

            let agent_child = unsafe { libc::fork() };
            if agent_child < 0 {
                unsafe { libc::_exit(12) };
            }
            if agent_child == 0 {
                sleep_ms_async_signal_safe(250);
                unsafe { libc::_exit(0) };
            }

            SHUTDOWN_REQUESTED.store(false, Ordering::Release);
            let exit_code = reap_until_agent_exits(agent_child);
            if exit_code != 0 {
                unsafe { libc::_exit(13) };
            }

            let mut trailing_status: libc::c_int = 0;
            let rem = unsafe { libc::waitpid(-1, &mut trailing_status, libc::WNOHANG) };
            if rem != -1 || io::Error::last_os_error().raw_os_error() != Some(libc::ECHILD) {
                unsafe { libc::_exit(14) };
            }
            unsafe { libc::_exit(0) };
        }

        assert_forked_child_exits_zero(subreaper_pid, "subreaper test");
    }

    fn assert_forked_child_exits_zero(pid: libc::pid_t, label: &str) {
        let mut status: libc::c_int = 0;
        loop {
            // SAFETY: Reaps the dedicated test subprocess created by the caller.
            let waited = unsafe { libc::waitpid(pid, &mut status, 0) };
            if waited == -1 && io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            assert_eq!(waited, pid, "waitpid on {label} child failed");
            break;
        }

        assert!(
            libc::WIFEXITED(status),
            "{label} subprocess did not exit cleanly (raw status={status})"
        );
        assert_eq!(
            libc::WEXITSTATUS(status),
            0,
            "{label} failed with step code {}",
            libc::WEXITSTATUS(status)
        );
    }

    #[test]
    fn populate_virtio_ports_creates_relative_symlinks_and_skips_unsafe_names() {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let root = std::env::temp_dir().join(format!(
            "tiny-init-vport-{}-{}",
            std::process::id(),
            nanos
        ));
        let sys_root = root.join("sys");
        let dev_root = root.join("dev");

        fs::create_dir_all(sys_root.join("class/virtio-ports/vport0p1")).unwrap();
        fs::create_dir_all(sys_root.join("class/virtio-ports/vport1p1")).unwrap();
        fs::create_dir_all(&dev_root).unwrap();
        fs::write(dev_root.join("vport0p1"), b"").unwrap();
        fs::write(dev_root.join("vport1p1"), b"").unwrap();
        fs::write(
            sys_root.join("class/virtio-ports/vport0p1/name"),
            b"org.minipod.agent.0\n",
        )
        .unwrap();
        fs::write(
            sys_root.join("class/virtio-ports/vport1p1/name"),
            b"../escape\n",
        )
        .unwrap();

        populate_virtio_ports(&sys_root, &dev_root).unwrap();

        let link = fs::read_link(dev_root.join("virtio-ports/org.minipod.agent.0")).unwrap();
        assert_eq!(link, Path::new("../vport0p1"));
        assert!(!root.join("escape").exists());

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn set_process_name_updates_proc_comm_and_validates_input() {
        assert!(set_process_name(b"tiny-init").is_err());
        assert!(set_process_name(b"0123456789abcdef\0").is_err());

        // Isolate `PR_SET_NAME` in a forked child so the test runner thread name stays untouched.
        // SAFETY: Child uses only `prctl`, `open`, `read`, `close`, and `_exit`.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork for set_process_name test failed");
        if pid == 0 {
            if set_process_name(b"tiny-init\0").is_err() {
                unsafe { libc::_exit(2) };
            }
            let fd = unsafe {
                libc::open(
                    b"/proc/self/comm\0".as_ptr().cast::<libc::c_char>(),
                    libc::O_RDONLY,
                )
            };
            if fd < 0 {
                unsafe { libc::_exit(3) };
            }
            let mut buf = [0u8; 32];
            let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast::<libc::c_void>(), buf.len()) };
            unsafe { libc::close(fd) };
            if n > 0 && &buf[..n as usize] == b"tiny-init\n" {
                unsafe { libc::_exit(0) };
            }
            unsafe { libc::_exit(4) };
        }

        assert_forked_child_exits_zero(pid, "set_process_name test");
    }
}
