//! Streaming Execution Supervisor for guest command execution, stdin/stdout/stderr
//! forwarding, incremental output budget capping, strict deadlines, and process-group kill.

use std::collections::{BTreeMap, HashMap};
use std::io::{self, Read, Write};
use std::process::{Child, Command, Stdio};
use std::sync::{mpsc, Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use sandbox_protocol::{ExecTargetWire, Message, StreamChannel, StreamId};

use crate::egress_listener::{container_proxy_url, guest_proxy_url, inject_default_proxy_env};
use crate::podman::{PodmanServiceManager, PODMAN_BIN, PODMAN_XDG_RUNTIME_DIR};
use crate::OutboundQueue;
#[cfg(unix)]
use crate::supervisor_unix;

const STREAM_READ_CHUNK_BYTES: usize = 64 * 1024;
const MAX_CONTAINER_TARGET_BYTES: usize = 128;
#[cfg(not(unix))]
const NON_UNIX_WAIT_POLL_INTERVAL: Duration = Duration::from_millis(10);

pub(crate) struct ExecSpec {
    #[cfg_attr(not(unix), allow(dead_code))]
    pub guest_exec_pids_max: Option<u32>,
    pub stream_id: StreamId,
    pub target: ExecTargetWire,
    pub argv: Vec<String>,
    pub env: BTreeMap<String, String>,
    pub cwd: Option<String>,
    pub user: Option<String>,
    pub deadline_ms: u64,
    pub stdout_budget_bytes: u64,
    pub stderr_budget_bytes: u64,
    pub proxy_port: Option<u16>,
}

pub(crate) enum StdinItem {
    Data { data: Vec<u8>, eof: bool },
    Close,
}

pub(crate) struct ActiveExec {
    stream_id: StreamId,
    stdin_tx: Mutex<Option<mpsc::Sender<StdinItem>>>,
    control: Arc<ExecControl>,
}

impl ActiveExec {
    pub(crate) fn new(stream_id: StreamId) -> (Arc<Self>, mpsc::Receiver<StdinItem>) {
        let (tx, rx) = mpsc::channel();
        let handle = Arc::new(Self {
            stream_id,
            stdin_tx: Mutex::new(Some(tx)),
            control: Arc::new(ExecControl::new()),
        });
        (handle, rx)
    }

    pub(crate) fn send_stdin(&self, data: Vec<u8>, eof: bool) {
        let mut guard = self.stdin_tx.lock().unwrap_or_else(|e| e.into_inner());
        let Some(tx) = guard.as_ref() else {
            return;
        };
        if tx.send(StdinItem::Data { data, eof }).is_err() || eof {
            *guard = None;
        }
    }

    pub(crate) fn close_stdin(&self) {
        let tx = self.stdin_tx.lock().unwrap_or_else(|e| e.into_inner()).take();
        if let Some(tx) = tx {
            let _ = tx.send(StdinItem::Close);
        }
    }

    pub(crate) fn cancel(&self, outbound: &OutboundQueue) {
        outbound.abort_stream(self.stream_id);
        self.control.trigger_cancel();
        self.close_stdin();
    }
}

#[derive(Default)]
struct ExecState {
    cancelled: bool,
    timed_out: bool,
    stdout_truncated: bool,
    stderr_truncated: bool,
    killed_by_supervisor: bool,
    child_exited: bool,
    exit_code: Option<i32>,
    stdout_done: bool,
    stderr_done: bool,
    #[cfg(unix)]
    pgid: Option<u32>,
    #[cfg(unix)]
    exec_scope: Option<Arc<supervisor_unix::ExecScope>>,
    #[cfg(not(unix))]
    child_handle: Option<Arc<Mutex<Option<Child>>>>,
}

struct ExecControl {
    state: Mutex<ExecState>,
    cv: Condvar,
}

impl ExecControl {
    fn new() -> Self {
        Self {
            state: Mutex::new(ExecState::default()),
            cv: Condvar::new(),
        }
    }

    fn trigger_cancel(&self) {
        let kill_target = {
            let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
            state.cancelled = true;
            let target = take_kill_target_locked(&mut state);
            self.cv.notify_all();
            target
        };
        if let Some(target) = kill_target {
            execute_kill(target);
        }
    }

    fn mark_truncated(&self, channel: StreamChannel) {
        let kill_target = {
            let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
            match channel {
                StreamChannel::Stdout => state.stdout_truncated = true,
                StreamChannel::Stderr => state.stderr_truncated = true,
                StreamChannel::Stdin => {}
            }
            let target = take_kill_target_locked(&mut state);
            self.cv.notify_all();
            target
        };
        if let Some(target) = kill_target {
            execute_kill(target);
        }
    }

    fn mark_pipe_done(&self, channel: StreamChannel) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        match channel {
            StreamChannel::Stdout => state.stdout_done = true,
            StreamChannel::Stderr => state.stderr_done = true,
            StreamChannel::Stdin => {}
        }
        self.cv.notify_all();
    }

    fn mark_child_exited(&self, code: Option<i32>) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.exit_code = code;
        state.child_exited = true;
        self.cv.notify_all();
    }
}

#[cfg(unix)]
type KillTarget = (u32, Arc<supervisor_unix::ExecScope>);
#[cfg(not(unix))]
type KillTarget = Arc<Mutex<Option<Child>>>;

fn take_kill_target_locked(state: &mut ExecState) -> Option<KillTarget> {
    if state.killed_by_supervisor {
        return None;
    }
    let still_active = !state.child_exited || !state.stdout_done || !state.stderr_done;
    if !still_active {
        return None;
    }
    #[cfg(unix)]
    {
        let pgid = state.pgid?;
        let scope = state.exec_scope.as_ref()?.clone();
        state.killed_by_supervisor = true;
        Some((pgid, scope))
    }
    #[cfg(not(unix))]
    {
        let handle = state.child_handle.as_ref()?.clone();
        state.killed_by_supervisor = true;
        Some(handle)
    }
}

fn execute_kill(target: KillTarget) {
    #[cfg(unix)]
    {
        let (pgid, scope) = target;
        scope.kill_all(pgid);
    }
    #[cfg(not(unix))]
    {
        let mut guard = target.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(ref mut child) = *guard {
            let _ = child.kill();
        }
    }
}

pub(crate) fn run_exec(
    spec: ExecSpec,
    handle: Arc<ActiveExec>,
    stdin_rx: mpsc::Receiver<StdinItem>,
    outbound: Arc<OutboundQueue>,
    active_execs: Arc<Mutex<HashMap<StreamId, Arc<ActiveExec>>>>,
    podman: Arc<PodmanServiceManager>,
) {
    let stream_id = spec.stream_id;
    let res = run_exec_inner(spec, &handle, stdin_rx, &outbound, &podman);

    // Ensure registry entry and stdin channel are cleared even if an error occurred.
    active_execs
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(&stream_id);
    handle.close_stdin();
    outbound.clear_stream(stream_id);

    if let Err(err) = res {
        eprintln!("[sandbox-agent] exec stream {stream_id} transport error: {err}");
    }
}

/// Validates a container name or ID passed to `podman exec` without shell/flag ambiguity.
pub(crate) fn validate_container_target(id_or_name: &str) -> Result<(), String> {
    if id_or_name.is_empty() {
        return Err("container target must not be empty".to_owned());
    }
    if id_or_name.len() > MAX_CONTAINER_TARGET_BYTES {
        return Err(format!(
            "container target exceeds {MAX_CONTAINER_TARGET_BYTES} bytes"
        ));
    }
    if id_or_name.starts_with('-') {
        return Err("container target must not start with '-'".to_owned());
    }
    if !id_or_name
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
    {
        return Err("container target must contain only ASCII [a-zA-Z0-9_.-]".to_owned());
    }
    Ok(())
}

pub(crate) fn resolve_exec_env(
    target: &ExecTargetWire,
    user_env: &BTreeMap<String, String>,
    proxy_port: Option<u16>,
) -> BTreeMap<String, String> {
    let Some(port) = proxy_port.filter(|&p| p > 0) else {
        return user_env.clone();
    };
    let proxy_url = match target {
        ExecTargetWire::Guest => guest_proxy_url(port),
        ExecTargetWire::Container { .. } => container_proxy_url(port),
    };
    inject_default_proxy_env(user_env, &proxy_url)
}

fn build_container_exec_args(id_or_name: &str, spec: &ExecSpec) -> Result<Vec<String>, String> {
    validate_container_target(id_or_name)?;
    if spec.argv.is_empty() {
        return Err("ExecStart argv must not be empty".to_owned());
    }

    let mut args = vec!["exec".to_owned(), "-i".to_owned()];
    if let Some(ref cwd) = spec.cwd {
        if cwd.contains('\0') {
            return Err("container exec workdir must not contain NUL bytes".to_owned());
        }
        args.push("--workdir".to_owned());
        args.push(cwd.clone());
    }
    if let Some(ref user) = spec.user {
        if user.contains('\0') {
            return Err("container exec user must not contain NUL bytes".to_owned());
        }
        args.push("--user".to_owned());
        args.push(user.clone());
    }
    let effective_env = resolve_exec_env(&spec.target, &spec.env, spec.proxy_port);
    for (key, val) in &effective_env {
        if key.is_empty() || key.contains('=') || key.contains('\0') {
            return Err(format!("invalid container exec env key '{key}'"));
        }
        if val.contains('\0') {
            return Err(format!(
                "container exec env value for '{key}' contains NUL byte"
            ));
        }
        args.push("--env".to_owned());
        args.push(format!("{key}={val}"));
    }
    args.push("--".to_owned());
    args.push(id_or_name.to_owned());
    args.extend(spec.argv.iter().cloned());
    Ok(args)
}

fn run_exec_inner(
    spec: ExecSpec,
    handle: &Arc<ActiveExec>,
    stdin_rx: mpsc::Receiver<StdinItem>,
    outbound: &Arc<OutboundQueue>,
    podman: &PodmanServiceManager,
) -> Result<(), sandbox_protocol::ProtocolError> {
    let stream_id = spec.stream_id;

    let Some((program, args)) = spec.argv.split_first() else {
        return emit_pre_spawn_failure(
            outbound,
            stream_id,
            127,
            b"ExecStart argv must not be empty\n",
            spec.stderr_budget_bytes,
        );
    };

    enum PreparedCommand {
        Guest {
            #[cfg(unix)]
            user: Option<supervisor_unix::UnixUser>,
        },
        Container {
            args: Vec<String>,
        },
    }

    let prepared = match &spec.target {
        ExecTargetWire::Guest => {
            #[cfg(unix)]
            let resolved_user = match spec.user.as_deref() {
                Some(user_spec) => match supervisor_unix::resolve_user(user_spec) {
                    Ok(ids) => Some(ids),
                    Err(reason) => {
                        let msg =
                            format!("failed to resolve ExecStart user '{user_spec}': {reason}\n");
                        return emit_pre_spawn_failure(
                            outbound,
                            stream_id,
                            126,
                            msg.as_bytes(),
                            spec.stderr_budget_bytes,
                        );
                    }
                },
                None => None,
            };

            #[cfg(not(unix))]
            if let Some(user_spec) = spec.user.as_deref() {
                let msg = format!(
                    "ExecStart user switching ('{user_spec}') is not supported on non-Unix hosts\n"
                );
                return emit_pre_spawn_failure(
                    outbound,
                    stream_id,
                    126,
                    msg.as_bytes(),
                    spec.stderr_budget_bytes,
                );
            }

            PreparedCommand::Guest {
                #[cfg(unix)]
                user: resolved_user,
            }
        }
        ExecTargetWire::Container { id_or_name } => {
            let container_args = match build_container_exec_args(id_or_name, &spec) {
                Ok(args) => args,
                Err(reason) => {
                    let msg = format!("{reason}\n");
                    return emit_pre_spawn_failure(
                        outbound,
                        stream_id,
                        125,
                        msg.as_bytes(),
                        spec.stderr_budget_bytes,
                    );
                }
            };
            PreparedCommand::Container {
                args: container_args,
            }
        }
    };

    if handle.control.state.lock().unwrap_or_else(|e| e.into_inner()).cancelled {
        outbound.send_stream_eof(stream_id, StreamChannel::Stdout)?;
        outbound.send_stream_eof(stream_id, StreamChannel::Stderr)?;
        return outbound.enqueue_exec_exit_after_data(
            stream_id,
            &Message::ExecExit {
                code: None,
                timed_out: false,
                stdout_truncated: false,
                stderr_truncated: false,
            },
        );
    }

    #[cfg(unix)]
    let exec_scope = {
        // podman exec joins an existing container's own cgroup. This budget is
        // for guest-exec descendants, including the rootless Codex executor.
        let is_container = matches!(spec.target, ExecTargetWire::Container { .. });
        let limit = if is_container {
            None
        } else {
            spec.guest_exec_pids_max
        };
        match supervisor_unix::ExecScope::prepare(stream_id, is_container, limit) {
            Ok(scope) => Arc::new(scope),
            Err(err) => {
                return emit_pre_spawn_failure(
                    outbound,
                    stream_id,
                    125,
                    format!("could not enforce guest exec PID limit: {err}\n").as_bytes(),
                    spec.stderr_budget_bytes,
                );
            }
        }
    };

    let (program_label, mut cmd) = match prepared {
        PreparedCommand::Guest {
            #[cfg(unix)]
            user,
        } => {
            let effective_env = resolve_exec_env(&spec.target, &spec.env, spec.proxy_port);
            let mut c = Command::new(program);
            c.args(args)
                .envs(&effective_env)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            if let Some(ref dir) = spec.cwd {
                c.current_dir(dir);
            }
            #[cfg(unix)]
            supervisor_unix::configure_exec_command(&mut c, user, &exec_scope);
            (program.as_str(), c)
        }
        PreparedCommand::Container { args: podman_args } => {
            if let Err(err) = podman.ensure_running() {
                let msg = format!("failed to start podman service for container exec: {err}\n");
                return emit_pre_spawn_failure(
                    outbound,
                    stream_id,
                    125,
                    msg.as_bytes(),
                    spec.stderr_budget_bytes,
                );
            }

            let mut c = Command::new(PODMAN_BIN);
            c.args(&podman_args)
                .env("XDG_RUNTIME_DIR", PODMAN_XDG_RUNTIME_DIR)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            #[cfg(unix)]
            supervisor_unix::configure_exec_command(&mut c, None, &exec_scope);
            (PODMAN_BIN, c)
        }
    };

    let mut child = match cmd.spawn() {
        Ok(child) => {
            #[cfg(unix)]
            exec_scope.close_spawn_fd();
            child
        }
        Err(err) => {
            let code = if err.kind() == io::ErrorKind::PermissionDenied {
                126
            } else {
                127
            };
            let msg = format!("failed to execute '{program_label}': {err}\n");
            return emit_pre_spawn_failure(
                outbound,
                stream_id,
                code,
                msg.as_bytes(),
                spec.stderr_budget_bytes,
            );
        }
    };

    let child_stdin = child.stdin.take();
    let child_stdout = child.stdout.take();
    let child_stderr = child.stderr.take();

    let deadline_at = Instant::now().checked_add(Duration::from_millis(spec.deadline_ms));

    #[cfg(unix)]
    {
        let pgid = child.id();
        exec_scope.record_leader(pgid);
        let immediate_kill = {
            let mut state = handle.control.state.lock().unwrap_or_else(|e| e.into_inner());
            state.pgid = Some(pgid);
            state.exec_scope = Some(Arc::clone(&exec_scope));
            if state.cancelled {
                state.killed_by_supervisor = true;
                true
            } else {
                false
            }
        };
        if immediate_kill {
            exec_scope.kill_all(pgid);
        }
        supervise_spawned_unix(
            child,
            pgid,
            exec_scope,
            child_stdin,
            child_stdout,
            child_stderr,
            stdin_rx,
            handle,
            outbound,
            stream_id,
            deadline_at,
            spec.stdout_budget_bytes,
            spec.stderr_budget_bytes,
        )
    }

    #[cfg(not(unix))]
    {
        let child_arc = Arc::new(Mutex::new(Some(child)));
        let immediate_kill = {
            let mut state = handle.control.state.lock().unwrap_or_else(|e| e.into_inner());
            state.child_handle = Some(child_arc.clone());
            if state.cancelled {
                state.killed_by_supervisor = true;
                true
            } else {
                false
            }
        };
        if immediate_kill {
            execute_kill(child_arc.clone());
        }
        supervise_spawned_non_unix(
            child_arc,
            child_stdin,
            child_stdout,
            child_stderr,
            stdin_rx,
            handle,
            outbound,
            stream_id,
            deadline_at,
            spec.stdout_budget_bytes,
            spec.stderr_budget_bytes,
        )
    }
}

#[cfg(unix)]
#[allow(clippy::too_many_arguments)]
fn supervise_spawned_unix(
    mut child: Child,
    pgid: u32,
    exec_scope: Arc<supervisor_unix::ExecScope>,
    child_stdin: Option<std::process::ChildStdin>,
    child_stdout: Option<std::process::ChildStdout>,
    child_stderr: Option<std::process::ChildStderr>,
    stdin_rx: mpsc::Receiver<StdinItem>,
    handle: &Arc<ActiveExec>,
    outbound: &Arc<OutboundQueue>,
    stream_id: StreamId,
    deadline_at: Option<Instant>,
    stdout_budget_bytes: u64,
    stderr_budget_bytes: u64,
) -> Result<(), sandbox_protocol::ProtocolError> {
    let control = &handle.control;
    thread::scope(|s| {
        let stdin_join = s.spawn(move || pump_stdin(child_stdin, stdin_rx, outbound, stream_id));
        let stdout_join = s.spawn(move || {
            pump_output(
                child_stdout,
                StreamChannel::Stdout,
                stdout_budget_bytes,
                outbound,
                stream_id,
                control,
            );
        });
        let stderr_join = s.spawn(move || {
            pump_output(
                child_stderr,
                StreamChannel::Stderr,
                stderr_budget_bytes,
                outbound,
                stream_id,
                control,
            );
        });
        let wait_join = s.spawn(move || {
            let code = match child.wait() {
                Ok(status) => status.code(),
                Err(_) => None,
            };
            control.mark_child_exited(code);
        });

        wait_deadline_and_completion(control, deadline_at, outbound, stream_id);

        let _ = stdout_join.join();
        let _ = stderr_join.join();
        let _ = wait_join.join();
        handle.close_stdin();
        let _ = stdin_join.join();
    });

    exec_scope.cleanup_after_reap(pgid);
    emit_final_exec_exit(outbound, stream_id, control)
}

#[cfg(not(unix))]
#[allow(clippy::too_many_arguments)]
fn supervise_spawned_non_unix(
    child_arc: Arc<Mutex<Option<Child>>>,
    child_stdin: Option<std::process::ChildStdin>,
    child_stdout: Option<std::process::ChildStdout>,
    child_stderr: Option<std::process::ChildStderr>,
    stdin_rx: mpsc::Receiver<StdinItem>,
    handle: &Arc<ActiveExec>,
    outbound: &Arc<OutboundQueue>,
    stream_id: StreamId,
    deadline_at: Option<Instant>,
    stdout_budget_bytes: u64,
    stderr_budget_bytes: u64,
) -> Result<(), sandbox_protocol::ProtocolError> {
    let control = &handle.control;
    thread::scope(|s| {
        let stdin_join = s.spawn(move || pump_stdin(child_stdin, stdin_rx, outbound, stream_id));
        let stdout_join = s.spawn(move || {
            pump_output(
                child_stdout,
                StreamChannel::Stdout,
                stdout_budget_bytes,
                outbound,
                stream_id,
                control,
            );
        });
        let stderr_join = s.spawn(move || {
            pump_output(
                child_stderr,
                StreamChannel::Stderr,
                stderr_budget_bytes,
                outbound,
                stream_id,
                control,
            );
        });
        let wait_join = s.spawn(move || {
            loop {
                let done = {
                    let mut guard = child_arc.lock().unwrap_or_else(|e| e.into_inner());
                    match guard.as_mut() {
                        Some(child) => match child.try_wait() {
                            Ok(Some(status)) => {
                                *guard = None;
                                Some(status.code())
                            }
                            Ok(None) => None,
                            Err(_) => {
                                *guard = None;
                                Some(None)
                            }
                        },
                        None => Some(None),
                    }
                };
                if let Some(code) = done {
                    control.mark_child_exited(code);
                    break;
                }
                thread::sleep(NON_UNIX_WAIT_POLL_INTERVAL);
            }
        });

        wait_deadline_and_completion(control, deadline_at, outbound, stream_id);

        let _ = stdout_join.join();
        let _ = stderr_join.join();
        let _ = wait_join.join();
        handle.close_stdin();
        let _ = stdin_join.join();
    });

    emit_final_exec_exit(outbound, stream_id, control)
}

fn wait_deadline_and_completion(
    control: &ExecControl,
    deadline_at: Option<Instant>,
    outbound: &OutboundQueue,
    stream_id: StreamId,
) {
    let mut state = control.state.lock().unwrap_or_else(|e| e.into_inner());
    loop {
        if state.child_exited && state.stdout_done && state.stderr_done {
            break;
        }
        if state.stdout_truncated || state.stderr_truncated || state.cancelled {
            outbound.abort_stream(stream_id);
        }
        if let Some(deadline) = deadline_at {
            let now = Instant::now();
            if now >= deadline {
                if !state.timed_out && (!state.child_exited || !state.stdout_done || !state.stderr_done) {
                    state.timed_out = true;
                }
                let target = take_kill_target_locked(&mut state);
                drop(state);
                outbound.abort_stream(stream_id);
                if let Some(t) = target {
                    execute_kill(t);
                }
                state = control.state.lock().unwrap_or_else(|e| e.into_inner());
                // After killing, wait until child exit and both output pipes finish closing.
                while !(state.child_exited && state.stdout_done && state.stderr_done) {
                    state = control.cv.wait(state).unwrap_or_else(|e| e.into_inner());
                }
                break;
            }
            let (next_state, _) = control
                .cv
                .wait_timeout(state, deadline.saturating_duration_since(now))
                .unwrap_or_else(|e| e.into_inner());
            state = next_state;
        } else {
            state = control.cv.wait(state).unwrap_or_else(|e| e.into_inner());
        }
    }
}

fn emit_final_exec_exit(
    outbound: &OutboundQueue,
    stream_id: StreamId,
    control: &ExecControl,
) -> Result<(), sandbox_protocol::ProtocolError> {
    let state = control.state.lock().unwrap_or_else(|e| e.into_inner());
    let killed = state.killed_by_supervisor
        || state.timed_out
        || state.cancelled
        || state.stdout_truncated
        || state.stderr_truncated;
    let exit_msg = Message::ExecExit {
        code: if killed { None } else { state.exit_code },
        timed_out: state.timed_out,
        stdout_truncated: state.stdout_truncated,
        stderr_truncated: state.stderr_truncated,
    };
    drop(state);
    outbound.enqueue_exec_exit_after_data(stream_id, &exit_msg)
}

fn emit_pre_spawn_failure(
    outbound: &OutboundQueue,
    stream_id: StreamId,
    code: i32,
    stderr_msg: &[u8],
    stderr_budget_bytes: u64,
) -> Result<(), sandbox_protocol::ProtocolError> {
    outbound.send_stream_eof(stream_id, StreamChannel::Stdout)?;

    let allowed = usize::try_from(stderr_budget_bytes).unwrap_or(usize::MAX);
    let truncated = stderr_msg.len() > allowed;
    let slice = &stderr_msg[..stderr_msg.len().min(allowed)];
    if slice.is_empty() {
        outbound.send_stream_eof(stream_id, StreamChannel::Stderr)?;
    } else {
        outbound.send_stream_data_final(stream_id, StreamChannel::Stderr, slice)?;
    }

    outbound.enqueue_exec_exit_after_data(
        stream_id,
        &Message::ExecExit {
            code: if truncated { None } else { Some(code) },
            timed_out: false,
            stdout_truncated: false,
            stderr_truncated: truncated,
        },
    )
}

fn pump_stdin(
    mut pipe: Option<std::process::ChildStdin>,
    rx: mpsc::Receiver<StdinItem>,
    outbound: &OutboundQueue,
    stream_id: StreamId,
) {
    while let Ok(item) = rx.recv() {
        match item {
            StdinItem::Close => break,
            StdinItem::Data { data, eof } => {
                let len = data.len();
                if let Some(ref mut stdin) = pipe {
                    if !data.is_empty()
                        && (stdin.write_all(&data).is_err() || stdin.flush().is_err())
                    {
                        pipe = None;
                        break;
                    }
                } else {
                    break;
                }
                if !eof && len > 0 {
                    let _ = outbound.send_stdin_credit(stream_id, len);
                }
                if eof {
                    pipe = None;
                    break;
                }
            }
        }
    }
    drop(pipe);
}

fn pump_output<R: Read>(
    pipe: Option<R>,
    channel: StreamChannel,
    budget_bytes: u64,
    outbound: &OutboundQueue,
    stream_id: StreamId,
    control: &ExecControl,
) {
    if let Some(mut reader) = pipe {
        let mut buf = vec![0u8; STREAM_READ_CHUNK_BYTES];
        let mut sent: u64 = 0;

        loop {
            let n = match reader.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => n,
                Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
                Err(_) => break,
            };

            let remaining = budget_bytes.saturating_sub(sent);
            let to_send = usize::try_from((n as u64).min(remaining)).unwrap_or(n);
            if to_send > 0 {
                if outbound
                    .send_stream_data(stream_id, channel, &buf[..to_send])
                    .is_err()
                {
                    break;
                }
                sent += to_send as u64;
            }
            if (n as u64) > remaining {
                outbound.abort_stream(stream_id);
                control.mark_truncated(channel);
                break;
            }
        }
        drop(reader);
    }

    let _ = outbound.send_stream_eof(stream_id, channel);
    control.mark_pipe_done(channel);
}

/// Resolves numeric `uid[:gid]` or `/etc/passwd` + `/etc/group` entries into `(uid, gid)`.
#[cfg(any(unix, test))]
pub(crate) fn resolve_user_ids_from_tables(
    spec: &str,
    passwd: Option<&str>,
    group: Option<&str>,
) -> Result<(u32, u32), String> {
    if spec.is_empty() || spec.contains('\0') || spec.chars().any(char::is_whitespace) {
        return Err("user specification must be non-empty without whitespace or NUL".to_owned());
    }

    let mut parts = spec.split(':');
    let user_part = parts.next().unwrap_or("");
    let group_part = parts.next();
    if parts.next().is_some() || user_part.is_empty() {
        return Err(format!("invalid user specification '{spec}'"));
    }

    let (uid, primary_gid) = if is_ascii_digits(user_part) {
        let uid = user_part
            .parse::<u32>()
            .map_err(|_| format!("invalid numeric uid '{user_part}'"))?;
        let gid = passwd
            .and_then(|table| lookup_passwd_by_uid(table, uid))
            .unwrap_or(0);
        (uid, gid)
    } else {
        let table = passwd.ok_or_else(|| {
            format!("cannot resolve username '{user_part}': /etc/passwd is unavailable")
        })?;
        lookup_passwd_by_name(table, user_part)
            .ok_or_else(|| format!("unknown user '{user_part}' in /etc/passwd"))?
    };

    let gid = match group_part {
        None => primary_gid,
        Some("") => return Err(format!("empty group in user specification '{spec}'")),
        Some(g) if is_ascii_digits(g) => g
            .parse::<u32>()
            .map_err(|_| format!("invalid numeric gid '{g}'"))?,
        Some(g) => {
            let table = group.ok_or_else(|| {
                format!("cannot resolve group '{g}': /etc/group is unavailable")
            })?;
            lookup_group_by_name(table, g)
                .ok_or_else(|| format!("unknown group '{g}' in /etc/group"))?
        }
    };

    Ok((uid, gid))
}

#[cfg(any(unix, test))]
fn is_ascii_digits(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())
}

#[cfg(any(unix, test))]
fn lookup_passwd_by_name(table: &str, name: &str) -> Option<(u32, u32)> {
    for line in table.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut fields = line.split(':');
        let entry_name = fields.next()?;
        let _pass = fields.next()?;
        let uid_str = fields.next()?;
        let gid_str = fields.next()?;
        if entry_name == name {
            let uid = uid_str.parse::<u32>().ok()?;
            let gid = gid_str.parse::<u32>().ok()?;
            return Some((uid, gid));
        }
    }
    None
}

#[cfg(any(unix, test))]
fn lookup_passwd_by_uid(table: &str, target_uid: u32) -> Option<u32> {
    for line in table.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut fields = line.split(':');
        let _name = fields.next()?;
        let _pass = fields.next()?;
        let uid = fields.next()?.parse::<u32>().ok()?;
        let gid = fields.next()?.parse::<u32>().ok()?;
        if uid == target_uid {
            return Some(gid);
        }
    }
    None
}

#[cfg(any(unix, test))]
fn lookup_group_by_name(table: &str, name: &str) -> Option<u32> {
    for line in table.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut fields = line.split(':');
        let entry_name = fields.next()?;
        let _pass = fields.next()?;
        let gid_str = fields.next()?;
        if entry_name == name {
            return gid_str.parse::<u32>().ok();
        }
    }
    None
}

#[cfg(any(target_os = "linux", test))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ProcStatEntry {
    pub pid: i32,
    pub state: char,
    pub ppid: i32,
    pub pgrp: i32,
    pub session: i32,
    pub starttime: u64,
}

#[cfg(any(target_os = "linux", test))]
pub(crate) fn parse_proc_stat_line(raw: &str) -> Option<ProcStatEntry> {
    let open = raw.find('(')?;
    let close = raw.rfind(')')?;
    if close <= open {
        return None;
    }
    let pid = raw[..open].trim().parse::<i32>().ok()?;
    let mut fields = raw[close + 1..].split_ascii_whitespace();
    let state = fields.next()?.chars().next()?;
    let ppid = fields.next()?.parse::<i32>().ok()?;
    let pgrp = fields.next()?.parse::<i32>().ok()?;
    let session = fields.next()?.parse::<i32>().ok()?;
    // Fields 3..=6 consumed above; field 22 (`starttime`) is 15 fields ahead (skip 7..=21).
    let starttime = fields.nth(15)?.parse::<u64>().ok()?;
    Some(ProcStatEntry {
        pid,
        state,
        ppid,
        pgrp,
        session,
        starttime,
    })
}

#[cfg(any(target_os = "linux", test))]
pub(crate) fn is_trusted_conmon_exe(exe_path: &str) -> bool {
    let cleaned = exe_path.strip_suffix(" (deleted)").unwrap_or(exe_path);
    matches!(
        cleaned,
        "/usr/bin/conmon"
            | "/usr/libexec/podman/conmon"
            | "/usr/lib/podman/conmon"
            | "/usr/local/libexec/podman/conmon"
            | "/usr/local/bin/conmon"
    )
}

#[cfg(any(target_os = "linux", test))]
pub(crate) fn extract_conmon_exec_pidfile<'a>(args: &'a [&'a str]) -> Option<&'a str> {
    if !args.iter().any(|&a| a == "-e" || a == "--exec") {
        return None;
    }
    let mut pidfile_path: Option<&str> = None;
    let mut idx = 0usize;
    while idx < args.len() {
        let arg = args[idx];
        if (arg == "-p" || arg == "--pidfile") && idx + 1 < args.len() {
            pidfile_path = Some(args[idx + 1]);
            break;
        }
        if let Some(rest) = arg.strip_prefix("--pidfile=") {
            pidfile_path = Some(rest);
            break;
        }
        idx += 1;
    }
    let path = pidfile_path?;
    if path.is_empty()
        || path.contains('\0')
        || path.split('/').any(|seg| seg == "..")
    {
        return None;
    }
    let trusted_root_dir = path.starts_with("/run/containers/")
        || path.starts_with("/run/libpod/")
        || path.starts_with("/var/run/containers/")
        || path.starts_with("/var/run/libpod/")
        || path.starts_with("/var/lib/containers/")
        || path.starts_with("/run/user/0/");
    trusted_root_dir.then_some(path)
}

#[cfg(any(target_os = "linux", test))]
pub(crate) fn expand_scoped_proc_closure(
    tracked: &mut HashMap<i32, u64>,
    table: &[ProcStatEntry],
    self_pid: i32,
    min_starttime: u64,
) {
    loop {
        let mut added = false;
        for entry in table {
            if entry.pid <= 1
                || entry.pid == self_pid
                || tracked.contains_key(&entry.pid)
                || entry.starttime < min_starttime
            {
                continue;
            }
            if tracked.contains_key(&entry.ppid)
                || (entry.pgrp > 1 && tracked.contains_key(&entry.pgrp))
                || (entry.session > 1 && tracked.contains_key(&entry.session))
            {
                tracked.insert(entry.pid, entry.starttime);
                added = true;
            }
        }
        if !added {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_container_spec() -> ExecSpec {
        let mut env = BTreeMap::new();
        env.insert("FOO".to_owned(), "bar=baz".to_owned());
        env.insert("Z_KEY".to_owned(), "val".to_owned());
        ExecSpec {
            guest_exec_pids_max: None,
            stream_id: StreamId(1),
            target: ExecTargetWire::Container {
                id_or_name: "web_1.app-0".to_owned(),
            },
            argv: vec!["/bin/sh".to_owned(), "-c".to_owned(), "echo hi".to_owned()],
            env,
            cwd: Some("/workspace".to_owned()),
            user: Some("1000:1000".to_owned()),
            deadline_ms: 5_000,
            stdout_budget_bytes: 4096,
            stderr_budget_bytes: 4096,
            proxy_port: None,
        }
    }

    #[test]
    fn validate_container_target_accepts_safe_names_and_rejects_unsafe_ones() {
        assert!(validate_container_target("c1").is_ok());
        assert!(validate_container_target("my-container_01.prod").is_ok());
        let max_id = "a".repeat(MAX_CONTAINER_TARGET_BYTES);
        assert!(validate_container_target(&max_id).is_ok());

        for bad in [
            "",
            "-leading",
            "--privileged",
            "foo/bar",
            "foo:bar",
            "foo bar",
            "foo\0bar",
            "café",
        ] {
            assert!(
                validate_container_target(bad).is_err(),
                "expected '{bad}' to be rejected"
            );
        }
        let too_long = "a".repeat(MAX_CONTAINER_TARGET_BYTES + 1);
        assert!(validate_container_target(&too_long).is_err());
    }

    #[test]
    fn build_container_exec_args_maps_workdir_user_env_and_double_dash() {
        let spec = sample_container_spec();
        let args = build_container_exec_args("web_1.app-0", &spec).unwrap();
        assert_eq!(
            args,
            vec![
                "exec",
                "-i",
                "--workdir",
                "/workspace",
                "--user",
                "1000:1000",
                "--env",
                "FOO=bar=baz",
                "--env",
                "Z_KEY=val",
                "--",
                "web_1.app-0",
                "/bin/sh",
                "-c",
                "echo hi",
            ]
        );
    }

    #[test]
    fn build_container_exec_args_rejects_nul_bytes_and_invalid_env_keys() {
        let mut bad_cwd = sample_container_spec();
        bad_cwd.cwd = Some("/app\0bad".to_owned());
        assert!(build_container_exec_args("c1", &bad_cwd).is_err());

        let mut bad_user = sample_container_spec();
        bad_user.user = Some("root\0".to_owned());
        assert!(build_container_exec_args("c1", &bad_user).is_err());

        let mut bad_env_key = sample_container_spec();
        bad_env_key.env.insert("BAD=KEY".to_owned(), "1".to_owned());
        assert!(build_container_exec_args("c1", &bad_env_key).is_err());

        let mut bad_env_val = sample_container_spec();
        bad_env_val.env.insert("OK".to_owned(), "a\0b".to_owned());
        assert!(build_container_exec_args("c1", &bad_env_val).is_err());
    }

    #[test]
    fn resolve_exec_env_injects_proxy_defaults_and_preserves_overrides() {
        let mut user_env = BTreeMap::new();
        user_env.insert("HTTP_PROXY".to_owned(), "http://custom-proxy:9999".to_owned());
        user_env.insert("http_proxy".to_owned(), String::new());
        user_env.insert("APP_MODE".to_owned(), "prod".to_owned());

        // Disabled proxy leaves user env untouched.
        assert_eq!(
            resolve_exec_env(&ExecTargetWire::Guest, &user_env, None),
            user_env
        );

        // Guest target injects http://127.0.0.1:<port> for missing keys.
        let guest_env = resolve_exec_env(&ExecTargetWire::Guest, &user_env, Some(3128));
        assert_eq!(guest_env.get("HTTP_PROXY").map(String::as_str), Some("http://custom-proxy:9999"));
        assert_eq!(guest_env.get("http_proxy").map(String::as_str), Some(""));
        assert_eq!(guest_env.get("APP_MODE").map(String::as_str), Some("prod"));
        assert_eq!(guest_env.get("HTTPS_PROXY").map(String::as_str), Some("http://127.0.0.1:3128"));
        assert_eq!(guest_env.get("ALL_PROXY").map(String::as_str), Some("http://127.0.0.1:3128"));
        assert_eq!(guest_env.get("https_proxy").map(String::as_str), Some("http://127.0.0.1:3128"));
        assert_eq!(guest_env.get("all_proxy").map(String::as_str), Some("http://127.0.0.1:3128"));
        assert_eq!(
            guest_env.get("NO_PROXY").map(String::as_str),
            Some(crate::egress_listener::DEFAULT_NO_PROXY)
        );
        assert_eq!(
            guest_env.get("no_proxy").map(String::as_str),
            Some(crate::egress_listener::DEFAULT_NO_PROXY)
        );

        // Container target injects http://10.88.0.1:<port> for bridged netavark containers.
        let mut container_spec = sample_container_spec();
        container_spec.env = user_env;
        container_spec.proxy_port = Some(3128);
        let args = build_container_exec_args("web_1.app-0", &container_spec).unwrap();
        assert!(args.contains(&"HTTP_PROXY=http://custom-proxy:9999".to_owned()));
        assert!(args.contains(&"http_proxy=".to_owned()));
        assert!(args.contains(&"HTTPS_PROXY=http://10.88.0.1:3128".to_owned()));
        assert!(args.contains(&"ALL_PROXY=http://10.88.0.1:3128".to_owned()));
        assert!(args.contains(&"https_proxy=http://10.88.0.1:3128".to_owned()));
        assert!(args.contains(&"all_proxy=http://10.88.0.1:3128".to_owned()));
        assert!(args.contains(&format!(
            "NO_PROXY={}",
            crate::egress_listener::DEFAULT_NO_PROXY
        )));
    }

    #[test]
    fn proc_closure_and_conmon_discovery_enforce_starttime_exe_exec_flag_and_root_pidfile_paths() {
        let stat_line =
            "4242 (weird ) name) S 100 4200 4200 0 -1 4194304 10 0 0 0 1 2 0 0 20 0 1 0 987654 12345 10";
        let parsed = parse_proc_stat_line(stat_line).unwrap();
        assert_eq!(
            parsed,
            ProcStatEntry {
                pid: 4242,
                state: 'S',
                ppid: 100,
                pgrp: 4200,
                session: 4200,
                starttime: 987_654,
            }
        );

        // Trusted vs spoofed conmon binary paths.
        assert!(is_trusted_conmon_exe("/usr/bin/conmon"));
        assert!(is_trusted_conmon_exe("/usr/libexec/podman/conmon (deleted)"));
        assert!(!is_trusted_conmon_exe("/tmp/conmon"));
        assert!(!is_trusted_conmon_exe("/workspace/fake-conmon"));

        // Requires `-e`/`--exec` and rejects `/tmp/` or `..` pidfile paths.
        assert_eq!(
            extract_conmon_exec_pidfile(&[
                "/usr/bin/conmon",
                "-e",
                "-p",
                "/run/containers/storage/overlay-containers/abc/userdata/exec_pid"
            ]),
            Some("/run/containers/storage/overlay-containers/abc/userdata/exec_pid")
        );
        assert_eq!(
            extract_conmon_exec_pidfile(&[
                "/usr/bin/conmon",
                "-p",
                "/run/containers/storage/exec_pid"
            ]),
            None,
            "non-exec conmon monitor without -e must be ignored"
        );
        assert_eq!(
            extract_conmon_exec_pidfile(&["/usr/bin/conmon", "-e", "-p", "/tmp/evil.pid"]),
            None,
            "world-writable /tmp pidfile must be rejected"
        );
        assert_eq!(
            extract_conmon_exec_pidfile(&[
                "/usr/bin/conmon",
                "-e",
                "--pidfile=/run/containers/../../tmp/evil.pid"
            ]),
            None
        );

        // Closure rejects processes started before `min_starttime` (even if PGID/SID matches).
        let mut tracked = HashMap::from([(200, 1000u64)]);
        let table = vec![
            ProcStatEntry {
                pid: 150,
                state: 'S',
                ppid: 1,
                pgrp: 200,
                session: 200,
                starttime: 500, // older than min_starttime=1000!
            },
            ProcStatEntry {
                pid: 201,
                state: 'S',
                ppid: 200,
                pgrp: 201,
                session: 201,
                starttime: 1005,
            },
            ProcStatEntry {
                pid: 202,
                state: 'S',
                ppid: 1,
                pgrp: 202,
                session: 201,
                starttime: 1010,
            },
        ];
        expand_scoped_proc_closure(&mut tracked, &table, 99, 1000);
        assert!(!tracked.contains_key(&150));
        assert_eq!(tracked.get(&201), Some(&1005));
        assert_eq!(tracked.get(&202), Some(&1010));
    }
}
