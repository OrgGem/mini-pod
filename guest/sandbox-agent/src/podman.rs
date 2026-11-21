//! Lazy, owner-restricted Podman system service supervisor (`unix:///run/podman/podman.sock`).

use std::path::Path;
#[cfg(any(unix, test))]
use std::path::PathBuf;
use std::sync::atomic::{AtomicU16, Ordering};

#[cfg(unix)]
use std::fs::{self, File, OpenOptions, Permissions};
#[cfg(unix)]
use std::io::{self, Read};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
#[cfg(unix)]
use std::os::unix::net::UnixStream;
#[cfg(unix)]
use std::process::{Child, Command, Stdio};
#[cfg(unix)]
use std::sync::Mutex;
#[cfg(unix)]
use std::thread;
#[cfg(unix)]
use std::time::{Duration, Instant};

#[cfg(unix)]
use crate::egress_listener::{default_proxy_env_pairs, guest_proxy_url};
#[cfg(unix)]
use crate::supervisor_unix::{configure_process_group, kill_process_group, signal_process_group};

pub(crate) const PODMAN_BIN: &str = "/usr/bin/podman";
#[cfg(unix)]
pub(crate) const PODMAN_RUN_DIR: &str = "/run/podman";
#[cfg(any(unix, test))]
pub(crate) const PODMAN_SOCKET_PATH: &str = "/run/podman/podman.sock";
#[cfg(unix)]
pub(crate) const PODMAN_LOG_PATH: &str = "/tmp/podman-service.log";
pub(crate) const PODMAN_XDG_RUNTIME_DIR: &str = "/run";

#[cfg(unix)]
const READINESS_TIMEOUT: Duration = Duration::from_secs(10);
#[cfg(unix)]
const READINESS_POLL_INTERVAL: Duration = Duration::from_millis(50);
#[cfg(unix)]
const SHUTDOWN_GRACE_TIMEOUT: Duration = Duration::from_secs(1);
#[cfg(unix)]
const SHUTDOWN_POLL_INTERVAL: Duration = Duration::from_millis(25);
#[cfg(unix)]
const LOG_TAIL_MAX_BYTES: usize = 2048;

#[cfg(unix)]
enum ServiceState {
    Idle,
    Running(Child),
    Shutdown,
}

/// Manages lazy startup and teardown of `podman system service` over an owner-only Unix socket.
pub(crate) struct PodmanServiceManager {
    #[cfg(unix)]
    podman_bin: PathBuf,
    #[cfg(unix)]
    run_dir: PathBuf,
    #[cfg(any(unix, test))]
    socket_path: PathBuf,
    #[cfg(unix)]
    log_path: PathBuf,
    #[cfg(unix)]
    xdg_runtime_dir: PathBuf,
    #[cfg(unix)]
    readiness_timeout: Duration,
    #[cfg(unix)]
    state: Mutex<ServiceState>,
    proxy_port: AtomicU16,
}

impl Default for PodmanServiceManager {
    fn default() -> Self {
        Self::new()
    }
}

impl PodmanServiceManager {
    /// Creates a lazy Podman manager using the standard guest runtime paths.
    pub(crate) fn new() -> Self {
        Self {
            #[cfg(unix)]
            podman_bin: PathBuf::from(PODMAN_BIN),
            #[cfg(unix)]
            run_dir: PathBuf::from(PODMAN_RUN_DIR),
            #[cfg(any(unix, test))]
            socket_path: PathBuf::from(PODMAN_SOCKET_PATH),
            #[cfg(unix)]
            log_path: PathBuf::from(PODMAN_LOG_PATH),
            #[cfg(unix)]
            xdg_runtime_dir: PathBuf::from(PODMAN_XDG_RUNTIME_DIR),
            #[cfg(unix)]
            readiness_timeout: READINESS_TIMEOUT,
            #[cfg(unix)]
            state: Mutex::new(ServiceState::Idle),
            proxy_port: AtomicU16::new(0),
        }
    }

    /// Configures the local guest HTTP egress proxy port (`None` disables proxy env injection).
    pub(crate) fn set_proxy_port(&self, port: Option<u16>) {
        self.proxy_port.store(port.unwrap_or(0), Ordering::Release);
    }

    /// Returns the active guest HTTP egress proxy port if configured.
    #[cfg(any(unix, test))]
    pub(crate) fn proxy_port(&self) -> Option<u16> {
        let port = self.proxy_port.load(Ordering::Acquire);
        (port > 0).then_some(port)
    }

    #[cfg(all(test, unix))]
    pub(crate) fn with_paths(
        podman_bin: PathBuf,
        run_dir: PathBuf,
        socket_path: PathBuf,
        log_path: PathBuf,
        xdg_runtime_dir: PathBuf,
        readiness_timeout: Duration,
    ) -> Self {
        Self {
            podman_bin,
            run_dir,
            socket_path,
            log_path,
            xdg_runtime_dir,
            readiness_timeout,
            state: Mutex::new(ServiceState::Idle),
            proxy_port: AtomicU16::new(0),
        }
    }

    /// Returns the guest Unix socket path used by Podman (`CONTAINER_HOST`).
    #[cfg(test)]
    pub(crate) fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    /// Ensures `podman system service` is running and accepting connections on the Unix socket.
    ///
    /// Lazily spawns `/usr/bin/podman system service --time=0 unix:///run/podman/podman.sock` on the
    /// first invocation so non-container cold boots pay zero Podman startup cost.
    #[cfg(unix)]
    pub(crate) fn ensure_running(&self) -> Result<&Path, String> {
        let mut guard = self
            .state
            .lock()
            .map_err(|_| "podman service state mutex poisoned".to_owned())?;

        match &mut *guard {
            ServiceState::Shutdown => {
                return Err("podman service is shutting down".to_owned());
            }
            ServiceState::Running(child) => match child.try_wait() {
                Ok(None) => return Ok(&self.socket_path),
                Ok(Some(status)) => {
                    eprintln!(
                        "[sandbox-agent] podman service exited unexpectedly ({status}); restarting"
                    );
                    *guard = ServiceState::Idle;
                }
                Err(err) => {
                    return Err(format!("failed to poll podman service child: {err}"));
                }
            },
            ServiceState::Idle => {}
        }

        let mut child = self.spawn_service()?;
        if let Err(err) = self.wait_for_ready(&mut child) {
            terminate_child_group(&mut child);
            return Err(err);
        }

        *guard = ServiceState::Running(child);
        Ok(&self.socket_path)
    }

    /// Non-Unix targets (checked on Windows host via `cargo check`) cannot host Podman Unix sockets.
    #[cfg(not(unix))]
    pub(crate) fn ensure_running(&self) -> Result<&Path, String> {
        Err("podman service Unix socket requires a Unix guest environment".to_owned())
    }

    /// Terminates the managed Podman service process group if it was started.
    #[cfg(unix)]
    pub(crate) fn shutdown(&self) {
        let child = match self.state.lock() {
            Ok(mut guard) => match std::mem::replace(&mut *guard, ServiceState::Shutdown) {
                ServiceState::Running(child) => Some(child),
                ServiceState::Idle | ServiceState::Shutdown => None,
            },
            Err(poisoned) => {
                let mut guard = poisoned.into_inner();
                match std::mem::replace(&mut *guard, ServiceState::Shutdown) {
                    ServiceState::Running(child) => Some(child),
                    ServiceState::Idle | ServiceState::Shutdown => None,
                }
            }
        };

        if let Some(mut child) = child {
            terminate_child_group(&mut child);
        }
    }

    /// No-op on non-Unix compilation targets.
    #[cfg(not(unix))]
    pub(crate) fn shutdown(&self) {}

    #[cfg(unix)]
    fn service_command(&self, stdout: std::fs::File, stderr: std::fs::File) -> Command {
        let socket_uri = format!("unix://{}", self.socket_path.display());
        let mut cmd = Command::new(&self.podman_bin);
        cmd.args(["system", "service", "--time=0", &socket_uri])
            .env("XDG_RUNTIME_DIR", &self.xdg_runtime_dir)
            .env_remove("CONTAINER_HOST")
            .stdin(Stdio::null())
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr));
        if let Some(port) = self.proxy_port() {
            cmd.envs(default_proxy_env_pairs(&guest_proxy_url(port)));
        }
        configure_process_group(&mut cmd);
        cmd
    }

    #[cfg(unix)]
    fn spawn_service(&self) -> Result<Child, String> {
        prepare_owner_only_dir(&self.run_dir)?;
        prepare_stale_socket(&self.socket_path)?;
        let log_file = open_log_file(&self.log_path)?;
        let log_err = log_file
            .try_clone()
            .map_err(|err| format!("failed to clone podman log fd: {err}"))?;

        let mut cmd = self.service_command(log_file, log_err);
        cmd.spawn().map_err(|err| {
            format!(
                "failed to spawn '{}' system service: {err}",
                self.podman_bin.display()
            )
        })
    }

    #[cfg(unix)]
    fn wait_for_ready(&self, child: &mut Child) -> Result<(), String> {
        let deadline = Instant::now() + self.readiness_timeout;
        loop {
            match child.try_wait() {
                Ok(Some(status)) => {
                    let tail = read_log_tail(&self.log_path);
                    return Err(format!(
                        "podman system service exited early with {status}{tail}"
                    ));
                }
                Ok(None) => {}
                Err(err) => {
                    return Err(format!("failed waiting on podman service status: {err}"));
                }
            }

            if UnixStream::connect(&self.socket_path).is_ok() {
                return Ok(());
            }

            if Instant::now() >= deadline {
                let tail = read_log_tail(&self.log_path);
                return Err(format!(
                    "podman socket '{}' did not become ready within {:?}{tail}",
                    self.socket_path.display(),
                    self.readiness_timeout
                ));
            }

            thread::sleep(READINESS_POLL_INTERVAL);
        }
    }
}

impl Drop for PodmanServiceManager {
    fn drop(&mut self) {
        self.shutdown();
    }
}

#[cfg(unix)]
fn prepare_owner_only_dir(dir: &Path) -> Result<(), String> {
    match fs::symlink_metadata(dir) {
        Ok(meta) => {
            if meta.file_type().is_symlink() || !meta.is_dir() {
                return Err(format!(
                    "refusing unsafe non-directory podman runtime path '{}'",
                    dir.display()
                ));
            }
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            fs::create_dir_all(dir)
                .map_err(|e| format!("failed to create '{}': {e}", dir.display()))?;
        }
        Err(err) => {
            return Err(format!("failed to inspect '{}': {err}", dir.display()));
        }
    }

    fs::set_permissions(dir, Permissions::from_mode(0o700)).map_err(|err| {
        format!(
            "failed to enforce 0700 permissions on '{}': {err}",
            dir.display()
        )
    })
}

#[cfg(unix)]
fn prepare_stale_socket(socket_path: &Path) -> Result<(), String> {
    match fs::symlink_metadata(socket_path) {
        Ok(meta) => {
            if meta.file_type().is_symlink() || meta.is_dir() {
                return Err(format!(
                    "refusing unsafe podman socket path '{}'",
                    socket_path.display()
                ));
            }
            fs::remove_file(socket_path).map_err(|err| {
                format!(
                    "failed to remove stale socket '{}': {err}",
                    socket_path.display()
                )
            })?;
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => {}
        Err(err) => {
            return Err(format!(
                "failed to stat socket '{}': {err}",
                socket_path.display()
            ));
        }
    }
    Ok(())
}

#[cfg(unix)]
fn open_log_file(log_path: &Path) -> Result<File, String> {
    if let Ok(meta) = fs::symlink_metadata(log_path) {
        if meta.file_type().is_symlink() || meta.is_dir() {
            return Err(format!(
                "refusing unsafe podman log path '{}'",
                log_path.display()
            ));
        }
    }
    OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(log_path)
        .map_err(|err| format!("failed to open podman log '{}': {err}", log_path.display()))
}

#[cfg(unix)]
fn terminate_child_group(child: &mut Child) {
    let pgid = child.id();
    signal_process_group(pgid, libc::SIGTERM);
    let deadline = Instant::now() + SHUTDOWN_GRACE_TIMEOUT;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return,
            Ok(None) if Instant::now() < deadline => {
                thread::sleep(SHUTDOWN_POLL_INTERVAL);
            }
            _ => break,
        }
    }
    kill_process_group(pgid);
    let _ = child.wait();
}

#[cfg(unix)]
fn read_log_tail(log_path: &Path) -> String {
    let Ok(mut file) = File::open(log_path) else {
        return String::new();
    };
    let mut buf = Vec::new();
    if file.read_to_end(&mut buf).is_err() || buf.is_empty() {
        return String::new();
    }
    let start = buf.len().saturating_sub(LOG_TAIL_MAX_BYTES);
    let snippet = String::from_utf8_lossy(&buf[start..]);
    let trimmed = snippet.trim();
    if trimmed.is_empty() {
        String::new()
    } else {
        format!("; podman log tail: {trimmed}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_manager_uses_expected_unix_socket_without_tcp() {
        let mgr = PodmanServiceManager::new();
        assert_eq!(mgr.socket_path(), Path::new(PODMAN_SOCKET_PATH));
        assert!(PODMAN_SOCKET_PATH.starts_with("/run/podman/"));
        assert_eq!(mgr.proxy_port(), None);
        mgr.set_proxy_port(Some(3128));
        assert_eq!(mgr.proxy_port(), Some(3128));
        mgr.set_proxy_port(None);
        assert_eq!(mgr.proxy_port(), None);
        mgr.shutdown();
    }

    #[cfg(not(unix))]
    #[test]
    fn non_unix_ensure_running_reports_unsupported_cleanly() {
        let mgr = PodmanServiceManager::new();
        let err = mgr
            .ensure_running()
            .expect_err("non-Unix host targets must reject Podman Unix socket startup");
        assert!(err.contains("Unix"), "unexpected error: {err}");
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlinked_socket_or_run_dir_and_reports_early_exit() {
        use std::os::unix::fs::symlink;
        use std::time::{SystemTime, UNIX_EPOCH};

        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let root = std::env::temp_dir().join(format!("podman-mgr-{}-{}", std::process::id(), nanos));
        fs::create_dir_all(&root).unwrap();
        let root = fs::canonicalize(root).unwrap();
        let false_binary = PathBuf::from(if cfg!(target_os = "macos") {
            "/usr/bin/false"
        } else {
            "/bin/false"
        });

        let real_dir = root.join("real");
        fs::create_dir_all(&real_dir).unwrap();
        let sym_run = root.join("sym-run");
        symlink(&real_dir, &sym_run).unwrap();

        let mgr_sym = PodmanServiceManager::with_paths(
            false_binary.clone(),
            sym_run,
            root.join("podman.sock"),
            root.join("podman.log"),
            root.clone(),
            Duration::from_millis(300),
        );
        let err = mgr_sym
            .ensure_running()
            .expect_err("symlinked runtime dir must be rejected");
        assert!(err.contains("unsafe"), "unexpected err: {err}");

        let mgr_early_exit = PodmanServiceManager::with_paths(
            false_binary,
            root.join("run-podman"),
            root.join("run-podman/podman.sock"),
            root.join("podman-early.log"),
            root.clone(),
            Duration::from_secs(2),
        );
        let err = mgr_early_exit
            .ensure_running()
            .expect_err("exiting mock binary must fail fast");
        assert!(err.contains("exited early"), "unexpected err: {err}");
        let mode = fs::metadata(root.join("run-podman"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o700);

        let _ = fs::remove_dir_all(&root);
    }

    #[cfg(unix)]
    #[test]
    fn service_command_clears_container_host_to_avoid_duplicate_uri_arg() {
        let mgr = PodmanServiceManager::new();
        let dev_null = fs::File::open("/dev/null").unwrap();
        let dev_null_err = dev_null.try_clone().unwrap();
        let cmd = mgr.service_command(dev_null, dev_null_err);
        let args: Vec<_> = cmd
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            args,
            vec![
                "system",
                "service",
                "--time=0",
                &format!("unix://{PODMAN_SOCKET_PATH}"),
            ]
        );
        let cleared_container_host = cmd
            .get_envs()
            .any(|(k, v)| k == "CONTAINER_HOST" && v.is_none());
        assert!(
            cleared_container_host,
            "service_command must explicitly remove CONTAINER_HOST for Podman 5 compatibility"
        );
        assert!(
            !cmd.get_envs().any(|(k, _)| k == "HTTP_PROXY"),
            "HTTP_PROXY must not be injected when egress proxy is disabled"
        );

        mgr.set_proxy_port(Some(3128));
        let dev_null_2 = fs::File::open("/dev/null").unwrap();
        let dev_null_err_2 = dev_null_2.try_clone().unwrap();
        let proxy_cmd = mgr.service_command(dev_null_2, dev_null_err_2);
        let envs: std::collections::HashMap<String, Option<String>> = proxy_cmd
            .get_envs()
            .map(|(k, v)| {
                (
                    k.to_string_lossy().into_owned(),
                    v.map(|val| val.to_string_lossy().into_owned()),
                )
            })
            .collect();
        for key in [
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "ALL_PROXY",
            "http_proxy",
            "https_proxy",
            "all_proxy",
        ] {
            assert_eq!(envs.get(key).and_then(|v| v.as_deref()), Some("http://127.0.0.1:3128"));
        }
        assert_eq!(
            envs.get("NO_PROXY").and_then(|v| v.as_deref()),
            Some(crate::egress_listener::DEFAULT_NO_PROXY)
        );
        assert_eq!(
            envs.get("no_proxy").and_then(|v| v.as_deref()),
            Some(crate::egress_listener::DEFAULT_NO_PROXY)
        );
    }
}
