//! Streaming Execution Supervisor for guest command execution, stdin/stdout/stderr
//! forwarding, incremental output budget capping, strict deadlines, and process-group kill.

use std::collections::{BTreeMap, HashMap};
use std::io::{self, Read, Write};
use std::process::{Child, Command, Stdio};
use std::sync::{mpsc, Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use sandbox_protocol::{ExecTargetWire, Message, StreamChannel, StreamId};

use crate::podman::{PodmanServiceManager, PODMAN_BIN, PODMAN_XDG_RUNTIME_DIR};
use crate::OutboundQueue;
#[cfg(unix)]
use crate::supervisor_unix;

const STREAM_READ_CHUNK_BYTES: usize = 64 * 1024;
const MAX_CONTAINER_TARGET_BYTES: usize = 128;
#[cfg(not(unix))]
const NON_UNIX_WAIT_POLL_INTERVAL: Duration = Duration::from_millis(10);

pub(crate) struct ExecSpec {
    pub stream_id: StreamId,
    pub target: ExecTargetWire,
    pub argv: Vec<String>,
    pub env: BTreeMap<String, String>,
    pub cwd: Option<String>,
    pub user: Option<String>,
    pub deadline_ms: u64,
    pub stdout_budget_bytes: u64,
    pub stderr_budget_bytes: u64,
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
type KillTarget = u32;
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
        state.killed_by_supervisor = true;
        Some(pgid)
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
        supervisor_unix::kill_process_group(target);
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
    for (key, val) in &spec.env {
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

    let (program_label, mut cmd) = match prepared {
        PreparedCommand::Guest {
            #[cfg(unix)]
            user,
        } => {
            let mut c = Command::new(program);
            c.args(args)
                .envs(&spec.env)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            if let Some(ref dir) = spec.cwd {
                c.current_dir(dir);
            }
            #[cfg(unix)]
            supervisor_unix::configure_command(&mut c, user);
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
            supervisor_unix::configure_command(&mut c, None);
            (PODMAN_BIN, c)
        }
    };

    let mut child = match cmd.spawn() {
        Ok(child) => child,
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
        let immediate_kill = {
            let mut state = handle.control.state.lock().unwrap_or_else(|e| e.into_inner());
            state.pgid = Some(pgid);
            if state.cancelled {
                state.killed_by_supervisor = true;
                true
            } else {
                false
            }
        };
        if immediate_kill {
            supervisor_unix::kill_process_group(pgid);
        }
        supervise_spawned_unix(
            child,
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

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_container_spec() -> ExecSpec {
        let mut env = BTreeMap::new();
        env.insert("FOO".to_owned(), "bar=baz".to_owned());
        env.insert("Z_KEY".to_owned(), "val".to_owned());
        ExecSpec {
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
}
