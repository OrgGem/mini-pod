#![deny(unsafe_code)]
//! Guest RPC daemon: streaming virtio-serial agent, Execution Supervisor, and safe tar copy.

mod copy_tar;
mod egress_listener;
mod podman;
mod supervisor;
#[cfg(unix)]
mod supervisor_unix;
mod tunnel;

use std::collections::{HashMap, HashSet};
use std::fs::OpenOptions;
use std::io::{self, Read, Write};
use std::process::ExitCode;
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use sandbox_protocol::{
    read_frame, write_frame, Frame, Lane, Message, PriorityFrameQueue, ProtocolError,
    StreamChannel, StreamId, INITIAL_STREAM_CREDIT_BYTES, MAX_FRAME_PAYLOAD_BYTES,
    PROTOCOL_VERSION,
};

use crate::copy_tar::{run_copy_in, run_copy_out, ActiveCopyIn};
use crate::egress_listener::EgressProxyManager;
use crate::podman::PodmanServiceManager;
use crate::supervisor::{run_exec, ActiveExec, ExecSpec};
use crate::tunnel::{run_tunnel, validate_connect_request, ActiveTunnel};

const VIRTIO_PORT_CANDIDATES: [&str; 2] =
    ["/dev/virtio-ports/org.minipod.agent.0", "/dev/vport0p1"];
const PORT_OPEN_TIMEOUT: Duration = Duration::from_secs(5);
const PORT_OPEN_POLL_INTERVAL: Duration = Duration::from_millis(50);

/// Maximum raw `StreamData` payload bytes per frame (`MAX_FRAME_PAYLOAD_BYTES` minus 2-byte header).
const MAX_STREAM_DATA_CHUNK_BYTES: usize = MAX_FRAME_PAYLOAD_BYTES as usize - 2;
/// Session-wide ceiling (`4 MiB`) on queued `Lane::Data` frames inside [`OutboundQueue`].
const MAX_OUTBOUND_DATA_QUEUE_BYTES: usize = 4 * 1024 * 1024;

#[derive(Default)]
struct OutboundState {
    queue: PriorityFrameQueue,
    data_queued_by_stream: HashMap<StreamId, usize>,
    credits: HashMap<(StreamId, u8), u64>,
    aborted_streams: HashSet<StreamId>,
    draining: bool,
    closed: bool,
    writer_err: Option<ProtocolError>,
}

pub(crate) struct OutboundQueue {
    state: Mutex<OutboundState>,
    cv: Condvar,
}

impl OutboundQueue {
    fn new() -> Self {
        Self {
            state: Mutex::new(OutboundState::default()),
            cv: Condvar::new(),
        }
    }

    pub(crate) fn push_frame(&self, frame: Frame) -> Result<(), ProtocolError> {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if frame.header.lane == Lane::Data {
            while !state.closed
                && state.queue.data_len() > 0
                && state.queue.data_bytes() >= MAX_OUTBOUND_DATA_QUEUE_BYTES
            {
                state = self.cv.wait(state).unwrap_or_else(|e| e.into_inner());
            }
        }
        if state.closed {
            return Err(closed_error(&state));
        }
        if frame.header.lane == Lane::Data {
            *state
                .data_queued_by_stream
                .entry(frame.header.stream_id)
                .or_insert(0) += 1;
        }
        state.queue.push(frame);
        self.cv.notify_all();
        Ok(())
    }

    pub(crate) fn push_message(
        &self,
        stream_id: StreamId,
        msg: &Message,
    ) -> Result<(), ProtocolError> {
        let frame = Frame::from_message(stream_id, msg)?;
        self.push_frame(frame)
    }

    pub(crate) fn send_stream_data(
        &self,
        stream_id: StreamId,
        channel: StreamChannel,
        bytes: &[u8],
    ) -> Result<(), ProtocolError> {
        self.send_stream_chunks(stream_id, channel, bytes, false)
    }

    pub(crate) fn send_stream_data_final(
        &self,
        stream_id: StreamId,
        channel: StreamChannel,
        bytes: &[u8],
    ) -> Result<(), ProtocolError> {
        if bytes.is_empty() {
            return self.send_stream_eof(stream_id, channel);
        }
        self.send_stream_chunks(stream_id, channel, bytes, true)
    }

    pub(crate) fn send_stream_eof(
        &self,
        stream_id: StreamId,
        channel: StreamChannel,
    ) -> Result<(), ProtocolError> {
        self.push_message(
            stream_id,
            &Message::StreamData {
                channel,
                eof: true,
                data: Vec::new(),
            },
        )
    }

    pub(crate) fn send_stdin_credit(
        &self,
        stream_id: StreamId,
        mut bytes: usize,
    ) -> Result<(), ProtocolError> {
        while bytes > 0 {
            let chunk = bytes.min(u32::MAX as usize);
            self.push_message(
                stream_id,
                &Message::StreamCredit {
                    channel: StreamChannel::Stdin,
                    bytes: chunk as u32,
                },
            )?;
            bytes -= chunk;
        }
        Ok(())
    }

    pub(crate) fn enqueue_exec_exit_after_data(
        &self,
        stream_id: StreamId,
        msg: &Message,
    ) -> Result<(), ProtocolError> {
        self.enqueue_control_after_data(stream_id, msg)
    }

    pub(crate) fn enqueue_control_after_data(
        &self,
        stream_id: StreamId,
        msg: &Message,
    ) -> Result<(), ProtocolError> {
        let frame = Frame::from_message(stream_id, msg)?;
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        while !state.closed
            && state
                .data_queued_by_stream
                .get(&stream_id)
                .copied()
                .unwrap_or(0)
                > 0
        {
            state = self.cv.wait(state).unwrap_or_else(|e| e.into_inner());
        }
        clear_stream_locked(&mut state, stream_id);
        if state.closed {
            return Err(closed_error(&state));
        }
        state.queue.push(frame);
        self.cv.notify_all();
        Ok(())
    }

    pub(crate) fn seed_default_credit(
        &self,
        stream_id: StreamId,
        channel: StreamChannel,
        bytes: u32,
    ) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state
            .credits
            .entry((stream_id, channel as u8))
            .or_insert_with(|| u64::from(bytes));
    }

    pub(crate) fn grant_credit(&self, stream_id: StreamId, channel: StreamChannel, bytes: u32) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state
            .credits
            .entry((stream_id, channel as u8))
            .and_modify(|rem| *rem = rem.saturating_add(u64::from(bytes)))
            .or_insert_with(|| u64::from(bytes));
        self.cv.notify_all();
    }

    pub(crate) fn abort_stream(&self, stream_id: StreamId) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.aborted_streams.insert(stream_id);
        self.cv.notify_all();
    }

    pub(crate) fn is_stream_aborted(&self, stream_id: StreamId) -> bool {
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .aborted_streams
            .contains(&stream_id)
    }

    pub(crate) fn clear_stream(&self, stream_id: StreamId) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        clear_stream_locked(&mut state, stream_id);
    }

    fn send_stream_chunks(
        &self,
        stream_id: StreamId,
        channel: StreamChannel,
        bytes: &[u8],
        mark_final_eof: bool,
    ) -> Result<(), ProtocolError> {
        let mut offset = 0;
        while offset < bytes.len() {
            let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
            let take = loop {
                if state.closed {
                    return Err(closed_error(&state));
                }
                if state.aborted_streams.contains(&stream_id) {
                    return Ok(());
                }
                if state.queue.data_len() > 0
                    && state.queue.data_bytes() >= MAX_OUTBOUND_DATA_QUEUE_BYTES
                {
                    state = self.cv.wait(state).unwrap_or_else(|e| e.into_inner());
                    continue;
                }
                let remaining = bytes.len() - offset;
                match state.credits.get_mut(&(stream_id, channel as u8)) {
                    None => break remaining.min(MAX_STREAM_DATA_CHUNK_BYTES),
                    Some(avail) if *avail > 0 => {
                        let allowed = usize::try_from(*avail).unwrap_or(usize::MAX);
                        let n = remaining.min(MAX_STREAM_DATA_CHUNK_BYTES).min(allowed);
                        *avail -= n as u64;
                        break n;
                    }
                    Some(_) => {
                        state = self.cv.wait(state).unwrap_or_else(|e| e.into_inner());
                    }
                }
            };

            let end = offset + take;
            let eof = mark_final_eof && end == bytes.len();
            let frame = Frame::from_message(
                stream_id,
                &Message::StreamData {
                    channel,
                    eof,
                    data: bytes[offset..end].to_vec(),
                },
            )?;
            *state
                .data_queued_by_stream
                .entry(stream_id)
                .or_insert(0) += 1;
            state.queue.push(frame);
            self.cv.notify_all();
            offset = end;
        }
        Ok(())
    }

    fn pop_for_writer(&self) -> Option<Frame> {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        loop {
            if state.closed && !state.draining {
                return None;
            }
            if let Some(frame) = state.queue.pop() {
                if frame.header.lane == Lane::Data {
                    let sid = frame.header.stream_id;
                    if let Some(count) = state.data_queued_by_stream.get_mut(&sid) {
                        *count = count.saturating_sub(1);
                        if *count == 0 {
                            state.data_queued_by_stream.remove(&sid);
                        }
                    }
                    self.cv.notify_all();
                }
                return Some(frame);
            }
            if state.draining {
                state.closed = true;
                self.cv.notify_all();
                return None;
            }
            state = self.cv.wait(state).unwrap_or_else(|e| e.into_inner());
        }
    }

    fn finish_and_drain(&self) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.draining = true;
        self.cv.notify_all();
    }

    fn fail_writer(&self, err: ProtocolError) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.closed = true;
        state.draining = false;
        if state.writer_err.is_none() {
            state.writer_err = Some(err);
        }
        self.cv.notify_all();
    }

    pub(crate) fn is_closed(&self) -> bool {
        self.state.lock().unwrap_or_else(|e| e.into_inner()).closed
    }

    fn take_writer_error(&self) -> Option<ProtocolError> {
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .writer_err
            .take()
    }
}

fn clear_stream_locked(state: &mut OutboundState, stream_id: StreamId) {
    state.credits.remove(&(stream_id, StreamChannel::Stdin as u8));
    state.credits.remove(&(stream_id, StreamChannel::Stdout as u8));
    state.credits.remove(&(stream_id, StreamChannel::Stderr as u8));
    state.aborted_streams.remove(&stream_id);
}

fn closed_error(state: &OutboundState) -> ProtocolError {
    match state.writer_err {
        Some(ref err) => ProtocolError::Io(io::Error::new(
            io::ErrorKind::BrokenPipe,
            format!("outbound writer closed: {err}"),
        )),
        None => ProtocolError::Io(io::Error::new(
            io::ErrorKind::BrokenPipe,
            "outbound writer closed",
        )),
    }
}

/// Runs one guest-initiated protocol session over `reader` and `writer`.
///
/// Protocol contract:
/// 1. Guest immediately sends `Hello` on `StreamId(0)` and waits for `HelloAck` on `StreamId(0)`
///    matching [`PROTOCOL_VERSION`].
/// 2. Concurrent reader/writer loops keep control frames (`Ping`, `ExecCancel`, `StreamCredit`,
///    `Shutdown`) responsive even while commands or tar streams are active.
/// 3. `ExecStart` runs under the Execution Supervisor with incremental stdout/stderr streaming,
///    budget capping, strict deadlines, and process-group kill on Unix.
/// 4. `CopyInStart` and `CopyOutStart` perform safe, symlink-hardened tar transfers bounded by
///    `max_bytes`.
/// 5. `Shutdown` cancels active work, replies with `Shutdown` on `StreamId(0)`, drains queued
///    frames, and returns `Ok(())`.
pub fn serve_session<R: Read + Send, W: Write + Send>(
    reader: &mut R,
    writer: &mut W,
) -> Result<(), ProtocolError> {
    // Guest initiates handshake so virtio-serial never drops early host frames before port open.
    send_message(
        writer,
        StreamId(0),
        &Message::Hello {
            version: PROTOCOL_VERSION,
        },
    )?;

    let ack_frame = read_frame(reader)?;
    if ack_frame.header.stream_id != StreamId(0) {
        return Err(ProtocolError::InvalidPayload(format!(
            "expected HelloAck on stream 0, got {}",
            ack_frame.header.stream_id
        )));
    }
    match ack_frame.decode_message()? {
        Message::HelloAck { version, .. } if version == PROTOCOL_VERSION => {}
        Message::HelloAck { version, .. } => {
            return Err(ProtocolError::UnsupportedVersion(version));
        }
        other => {
            return Err(ProtocolError::InvalidPayload(format!(
                "expected HelloAck during handshake, got {:?}",
                other.kind()
            )));
        }
    }

    let outbound = Arc::new(OutboundQueue::new());
    let podman = Arc::new(PodmanServiceManager::new());
    let active_execs: Arc<Mutex<HashMap<StreamId, Arc<ActiveExec>>>> =
        Arc::new(Mutex::new(HashMap::new()));
    let active_copy_ins: Arc<Mutex<HashMap<StreamId, Arc<ActiveCopyIn>>>> =
        Arc::new(Mutex::new(HashMap::new()));
    let active_copy_outs: Arc<Mutex<HashSet<StreamId>>> = Arc::new(Mutex::new(HashSet::new()));
    let active_tunnels: Arc<Mutex<HashMap<StreamId, Arc<ActiveTunnel>>>> =
        Arc::new(Mutex::new(HashMap::new()));
    let egress_proxy = Arc::new(EgressProxyManager::new(
        outbound.clone(),
        active_tunnels.clone(),
    ));

    let session_result = thread::scope(|scope| {
        let writer_outbound = outbound.clone();
        let writer_handle = scope.spawn(move || {
            while let Some(frame) = writer_outbound.pop_for_writer() {
                if let Err(err) = write_frame(writer, &frame) {
                    writer_outbound.fail_writer(err);
                    return;
                }
            }
        });

        let mut workers = Vec::new();
        let mut session_res: Result<(), ProtocolError> = Ok(());
        let mut shutdown_requested = false;

        loop {
            reap_finished_workers(&mut workers);

            let frame = match read_frame(reader) {
                Ok(frame) => frame,
                Err(ProtocolError::Eof) => break,
                Err(err) => {
                    session_res = Err(err);
                    break;
                }
            };

            let stream_id = frame.header.stream_id;
            let msg = match frame.decode_message() {
                Ok(msg) => msg,
                Err(err) => {
                    session_res = Err(err);
                    break;
                }
            };

            match msg {
                Message::Ping { seq } => {
                    if let Err(err) = outbound.push_message(stream_id, &Message::Pong { seq }) {
                        session_res = Err(err);
                        break;
                    }
                }
                Message::ExecStart {
                    target,
                    argv,
                    env,
                    cwd,
                    user,
                    deadline_ms,
                    stdout_budget_bytes,
                    stderr_budget_bytes,
                } => {
                    if stream_id == StreamId(0)
                        || is_stream_active(
                            &active_execs,
                            &active_copy_ins,
                            &active_copy_outs,
                            &active_tunnels,
                            stream_id,
                        )
                    {
                        session_res = Err(ProtocolError::InvalidPayload(format!(
                            "invalid or duplicate stream_id {stream_id} for ExecStart"
                        )));
                        break;
                    }
                    outbound.seed_default_credit(
                        stream_id,
                        StreamChannel::Stdout,
                        INITIAL_STREAM_CREDIT_BYTES,
                    );
                    outbound.seed_default_credit(
                        stream_id,
                        StreamChannel::Stderr,
                        INITIAL_STREAM_CREDIT_BYTES,
                    );
                    let (handle, stdin_rx) = ActiveExec::new(stream_id);
                    active_execs
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .insert(stream_id, handle.clone());

                    let spec = ExecSpec {
                        stream_id,
                        target,
                        argv,
                        env,
                        cwd,
                        user,
                        deadline_ms,
                        stdout_budget_bytes,
                        stderr_budget_bytes,
                        proxy_port: egress_proxy.active_proxy_port(),
                    };
                    let worker_outbound = outbound.clone();
                    let worker_execs = active_execs.clone();
                    let worker_podman = podman.clone();
                    workers.push(scope.spawn(move || {
                        run_exec(
                            spec,
                            handle,
                            stdin_rx,
                            worker_outbound,
                            worker_execs,
                            worker_podman,
                        );
                    }));
                }
                Message::ExecCancel => {
                    outbound.abort_stream(stream_id);
                    let handle = active_execs
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .get(&stream_id)
                        .cloned();
                    if let Some(handle) = handle {
                        handle.cancel(&outbound);
                    }
                }
                Message::StreamData {
                    channel: StreamChannel::Stdin,
                    eof,
                    data,
                } => {
                    let exec_target = active_execs
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .get(&stream_id)
                        .cloned();
                    if let Some(exec_handle) = exec_target {
                        exec_handle.send_stdin(data, eof);
                    } else {
                        let copy_target = active_copy_ins
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .get(&stream_id)
                            .cloned();
                        if let Some(copy_handle) = copy_target {
                            copy_handle.push_chunk(data, eof);
                        } else {
                            let tunnel_target = active_tunnels
                                .lock()
                                .unwrap_or_else(|e| e.into_inner())
                                .get(&stream_id)
                                .cloned();
                            if let Some(tunnel_handle) = tunnel_target {
                                tunnel_handle.push_stdin(data, eof, &outbound);
                            }
                        }
                    }
                }
                Message::StreamData { channel, .. } => {
                    session_res = Err(ProtocolError::InvalidPayload(format!(
                        "unexpected host-to-guest StreamData on channel {channel:?}"
                    )));
                    break;
                }
                Message::StreamCredit { channel, bytes } => {
                    outbound.grant_credit(stream_id, channel, bytes);
                }
                Message::CopyInStart {
                    dst_guest,
                    max_bytes,
                } => {
                    if stream_id == StreamId(0)
                        || is_stream_active(
                            &active_execs,
                            &active_copy_ins,
                            &active_copy_outs,
                            &active_tunnels,
                            stream_id,
                        )
                    {
                        session_res = Err(ProtocolError::InvalidPayload(format!(
                            "invalid or duplicate stream_id {stream_id} for CopyInStart"
                        )));
                        break;
                    }
                    let (handle, rx) = ActiveCopyIn::new();
                    active_copy_ins
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .insert(stream_id, handle);

                    let worker_outbound = outbound.clone();
                    let worker_copies = active_copy_ins.clone();
                    workers.push(scope.spawn(move || {
                        run_copy_in(
                            stream_id,
                            dst_guest,
                            max_bytes,
                            rx,
                            worker_outbound,
                            worker_copies,
                        );
                    }));
                }
                Message::CopyOutStart {
                    src_guest,
                    max_bytes,
                } => {
                    if stream_id == StreamId(0)
                        || is_stream_active(
                            &active_execs,
                            &active_copy_ins,
                            &active_copy_outs,
                            &active_tunnels,
                            stream_id,
                        )
                    {
                        session_res = Err(ProtocolError::InvalidPayload(format!(
                            "invalid or duplicate stream_id {stream_id} for CopyOutStart"
                        )));
                        break;
                    }
                    active_copy_outs
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .insert(stream_id);
                    outbound.seed_default_credit(
                        stream_id,
                        StreamChannel::Stdout,
                        INITIAL_STREAM_CREDIT_BYTES,
                    );
                    let worker_outbound = outbound.clone();
                    let worker_copy_outs = active_copy_outs.clone();
                    workers.push(scope.spawn(move || {
                        run_copy_out(
                            stream_id,
                            src_guest,
                            max_bytes,
                            worker_outbound,
                            worker_copy_outs,
                        );
                    }));
                }
                Message::Shutdown => {
                    shutdown_requested = true;
                    break;
                }
                Message::ConnectStart { target } => {
                    let in_use = is_stream_active(
                        &active_execs,
                        &active_copy_ins,
                        &active_copy_outs,
                        &active_tunnels,
                        stream_id,
                    );
                    if let Err(reason) = validate_connect_request(stream_id, target, in_use) {
                        if let Err(err) = outbound.push_message(
                            stream_id,
                            &Message::ConnectError { message: reason },
                        ) {
                            session_res = Err(err);
                            break;
                        }
                    } else {
                        outbound.seed_default_credit(
                            stream_id,
                            StreamChannel::Stdout,
                            INITIAL_STREAM_CREDIT_BYTES,
                        );
                        let (handle, stdin_rx) = ActiveTunnel::new(stream_id);
                        active_tunnels
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .insert(stream_id, handle.clone());
                        let worker_outbound = outbound.clone();
                        let worker_tunnels = active_tunnels.clone();
                        let worker_podman = podman.clone();
                        workers.push(scope.spawn(move || {
                            run_tunnel(
                                stream_id,
                                target,
                                handle,
                                stdin_rx,
                                worker_outbound,
                                worker_tunnels,
                                worker_podman,
                            );
                        }));
                    }
                }
                Message::StreamClose => {
                    let tunnel = active_tunnels
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .remove(&stream_id);
                    if let Some(handle) = tunnel {
                        handle.close(&outbound);
                    }
                    let copy_in = {
                        let guard = active_copy_ins.lock().unwrap_or_else(|e| e.into_inner());
                        let handle = guard.get(&stream_id).cloned();
                        if handle.is_some() {
                            outbound.abort_stream(stream_id);
                        }
                        handle
                    };
                    if let Some(handle) = copy_in {
                        handle.abort();
                    }
                    {
                        let guard = active_copy_outs.lock().unwrap_or_else(|e| e.into_inner());
                        if guard.contains(&stream_id) {
                            outbound.abort_stream(stream_id);
                        }
                    }
                }
                Message::ConfigureNetwork {
                    enable_egress_proxy,
                    proxy_port,
                } => {
                    if stream_id != StreamId(0) {
                        session_res = Err(ProtocolError::InvalidPayload(format!(
                            "ConfigureNetwork must arrive on stream 0, got {stream_id}"
                        )));
                        break;
                    }
                    match egress_proxy.configure(enable_egress_proxy, proxy_port) {
                        Ok(bound_port) => {
                            podman.set_proxy_port((bound_port > 0).then_some(bound_port));
                            if let Err(err) = outbound.push_message(
                                StreamId(0),
                                &Message::ConfigureNetworkAck {
                                    proxy_port: bound_port,
                                },
                            ) {
                                session_res = Err(err);
                                break;
                            }
                        }
                        Err(err) => {
                            session_res = Err(err);
                            break;
                        }
                    }
                }
                Message::ConnectAck => {
                    let tunnel = active_tunnels
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .get(&stream_id)
                        .cloned();
                    if let Some(handle) = tunnel {
                        handle.resolve_connect(Ok(()));
                    }
                }
                Message::ConnectError { message } => {
                    let tunnel = active_tunnels
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .remove(&stream_id);
                    if let Some(handle) = tunnel {
                        handle.resolve_connect(Err(message));
                        handle.close(&outbound);
                    }
                }
                other => {
                    session_res = Err(ProtocolError::InvalidPayload(format!(
                        "unsupported host-to-guest message {:?}",
                        other.kind()
                    )));
                    break;
                }
            }
        }

        egress_proxy.shutdown();

        if shutdown_requested || session_res.is_err() || outbound.is_closed() {
            cancel_all_active(
                &active_execs,
                &active_copy_ins,
                &active_copy_outs,
                &active_tunnels,
                &outbound,
            );
        }

        for handle in workers {
            let _ = handle.join();
        }

        if shutdown_requested && session_res.is_ok() {
            if let Err(err) = outbound.push_message(StreamId(0), &Message::Shutdown) {
                session_res = Err(err);
            }
        }

        outbound.finish_and_drain();
        let _ = writer_handle.join();

        if session_res.is_err() {
            session_res
        } else if let Some(writer_err) = outbound.take_writer_error() {
            Err(writer_err)
        } else {
            Ok(())
        }
    });

    podman.shutdown();
    session_result
}

fn is_stream_active(
    active_execs: &Mutex<HashMap<StreamId, Arc<ActiveExec>>>,
    active_copy_ins: &Mutex<HashMap<StreamId, Arc<ActiveCopyIn>>>,
    active_copy_outs: &Mutex<HashSet<StreamId>>,
    active_tunnels: &Mutex<HashMap<StreamId, Arc<ActiveTunnel>>>,
    stream_id: StreamId,
) -> bool {
    active_execs
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .contains_key(&stream_id)
        || active_copy_ins
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .contains_key(&stream_id)
        || active_copy_outs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .contains(&stream_id)
        || active_tunnels
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .contains_key(&stream_id)
}

fn cancel_all_active(
    active_execs: &Mutex<HashMap<StreamId, Arc<ActiveExec>>>,
    active_copy_ins: &Mutex<HashMap<StreamId, Arc<ActiveCopyIn>>>,
    active_copy_outs: &Mutex<HashSet<StreamId>>,
    active_tunnels: &Mutex<HashMap<StreamId, Arc<ActiveTunnel>>>,
    outbound: &OutboundQueue,
) {
    let execs: Vec<_> = active_execs
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .values()
        .cloned()
        .collect();
    for handle in execs {
        handle.cancel(outbound);
    }

    let copy_ins: Vec<_> = {
        let guard = active_copy_ins.lock().unwrap_or_else(|e| e.into_inner());
        for &sid in guard.keys() {
            outbound.abort_stream(sid);
        }
        guard.values().cloned().collect()
    };
    for handle in copy_ins {
        handle.abort();
    }

    {
        let guard = active_copy_outs.lock().unwrap_or_else(|e| e.into_inner());
        for &sid in guard.iter() {
            outbound.abort_stream(sid);
        }
    }

    let tunnels: Vec<_> = active_tunnels
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .values()
        .cloned()
        .collect();
    for handle in tunnels {
        handle.close(outbound);
    }
}

fn reap_finished_workers(workers: &mut Vec<thread::ScopedJoinHandle<'_, ()>>) {
    let mut i = 0;
    while i < workers.len() {
        if workers[i].is_finished() {
            let handle = workers.swap_remove(i);
            let _ = handle.join();
        } else {
            i += 1;
        }
    }
}

fn send_message<W: Write>(
    writer: &mut W,
    stream_id: StreamId,
    msg: &Message,
) -> Result<(), ProtocolError> {
    let frame = Frame::from_message(stream_id, msg)?;
    write_frame(writer, &frame)
}

fn open_virtio_port() -> io::Result<(std::fs::File, &'static str)> {
    let deadline = Instant::now() + PORT_OPEN_TIMEOUT;
    let mut last_err = None;
    loop {
        for &path in &VIRTIO_PORT_CANDIDATES {
            match OpenOptions::new().read(true).write(true).open(path) {
                Ok(file) => return Ok((file, path)),
                Err(err) => last_err = Some(err),
            }
        }
        if Instant::now() >= deadline {
            return Err(last_err.unwrap_or_else(|| {
                io::Error::new(io::ErrorKind::NotFound, "no virtio-serial port available")
            }));
        }
        thread::sleep(PORT_OPEN_POLL_INTERVAL);
    }
}

fn main() -> ExitCode {
    let (mut reader, path) = match open_virtio_port() {
        Ok(port) => port,
        Err(err) => {
            eprintln!("[sandbox-agent] failed to open virtio-serial port: {err}");
            return ExitCode::FAILURE;
        }
    };
    let mut writer = match reader.try_clone() {
        Ok(dup) => dup,
        Err(err) => {
            eprintln!("[sandbox-agent] failed to clone virtio-serial handle for {path}: {err}");
            return ExitCode::FAILURE;
        }
    };

    eprintln!("[sandbox-agent] connected on {path}");
    match serve_session(&mut reader, &mut writer) {
        Ok(()) => {
            eprintln!("[sandbox-agent] session exited cleanly");
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("[sandbox-agent] session error: {err}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sandbox_protocol::ExecTargetWire;
    use std::collections::{BTreeMap, VecDeque};
    use std::fs;
    use std::io::Cursor;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::mpsc::{self, Receiver, Sender};

    static TEST_SEQ: AtomicU64 = AtomicU64::new(0);

    struct TestTempDir(PathBuf);

    impl TestTempDir {
        fn new(label: &str) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "minipod-agent-test-{label}-{}-{}",
                std::process::id(),
                TEST_SEQ.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir_all(&dir).expect("create test temp dir");
            #[cfg(target_os = "macos")]
            let dir = fs::canonicalize(dir).expect("canonicalize test temp dir");
            Self(dir)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TestTempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    struct ChannelReader {
        rx: Receiver<Vec<u8>>,
        buf: VecDeque<u8>,
    }

    impl Read for ChannelReader {
        fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
            while self.buf.is_empty() {
                match self.rx.recv() {
                    Ok(chunk) if chunk.is_empty() => continue,
                    Ok(chunk) => self.buf.extend(chunk),
                    Err(_) => return Ok(0),
                }
            }
            let n = out.len().min(self.buf.len());
            for slot in &mut out[..n] {
                *slot = self.buf.pop_front().expect("checked non-empty");
            }
            Ok(n)
        }
    }

    struct ChannelWriter {
        tx: Sender<Vec<u8>>,
    }

    impl Write for ChannelWriter {
        fn write(&mut self, data: &[u8]) -> io::Result<usize> {
            self.tx
                .send(data.to_vec())
                .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "channel closed"))?;
            Ok(data.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn duplex_pair() -> ((ChannelReader, ChannelWriter), (ChannelReader, ChannelWriter)) {
        let (a_to_b_tx, a_to_b_rx) = mpsc::channel();
        let (b_to_a_tx, b_to_a_rx) = mpsc::channel();
        (
            (
                ChannelReader {
                    rx: b_to_a_rx,
                    buf: VecDeque::new(),
                },
                ChannelWriter { tx: a_to_b_tx },
            ),
            (
                ChannelReader {
                    rx: a_to_b_rx,
                    buf: VecDeque::new(),
                },
                ChannelWriter { tx: b_to_a_tx },
            ),
        )
    }

    fn start_test_session() -> (
        ChannelReader,
        ChannelWriter,
        thread::JoinHandle<Result<(), ProtocolError>>,
    ) {
        let ((mut host_rx, mut host_tx), (mut agent_rx, mut agent_tx)) = duplex_pair();
        let agent = thread::spawn(move || serve_session(&mut agent_rx, &mut agent_tx));

        let hello = read_frame(&mut host_rx).expect("guest must emit Hello first");
        assert_eq!(hello.header.stream_id, StreamId(0));
        assert_eq!(
            hello.decode_message().unwrap(),
            Message::Hello {
                version: PROTOCOL_VERSION
            }
        );

        send_message(
            &mut host_tx,
            StreamId(0),
            &Message::HelloAck {
                version: PROTOCOL_VERSION,
                features: 0,
            },
        )
        .unwrap();
        (host_rx, host_tx, agent)
    }

    fn shell_cmd(script: &str) -> Vec<String> {
        #[cfg(windows)]
        {
            vec!["cmd".to_owned(), "/C".to_owned(), script.to_owned()]
        }
        #[cfg(unix)]
        {
            vec!["/bin/sh".to_owned(), "-c".to_owned(), script.to_owned()]
        }
    }

    fn encode_frames(items: &[(StreamId, Message)]) -> Vec<u8> {
        let mut wire = Vec::new();
        for (stream_id, msg) in items {
            let frame = Frame::from_message(*stream_id, msg).expect("valid test frame");
            write_frame(&mut wire, &frame).expect("encode to vec");
        }
        wire
    }

    fn guest_exec_start(argv: Vec<String>) -> Message {
        Message::ExecStart {
            target: ExecTargetWire::Guest,
            argv,
            env: BTreeMap::new(),
            cwd: None,
            user: None,
            deadline_ms: 15_000,
            stdout_budget_bytes: 1_048_576,
            stderr_budget_bytes: 1_048_576,
        }
    }

    fn collect_exec_response(
        host_rx: &mut ChannelReader,
        stream_id: StreamId,
    ) -> (Vec<u8>, Vec<u8>, bool, bool, Message) {
        let mut stdout_bytes = Vec::new();
        let mut stderr_bytes = Vec::new();
        let mut stdout_eof = false;
        let mut stderr_eof = false;
        let exit_msg = loop {
            let frame = read_frame(host_rx).expect("exec response frame");
            assert_eq!(frame.header.stream_id, stream_id);
            match frame.decode_message().unwrap() {
                Message::StreamData {
                    channel: StreamChannel::Stdout,
                    eof,
                    data,
                } => {
                    stdout_bytes.extend_from_slice(&data);
                    if eof {
                        stdout_eof = true;
                    }
                }
                Message::StreamData {
                    channel: StreamChannel::Stderr,
                    eof,
                    data,
                } => {
                    stderr_bytes.extend_from_slice(&data);
                    if eof {
                        stderr_eof = true;
                    }
                }
                msg @ Message::ExecExit { .. } => break msg,
                other => panic!("unexpected frame during exec: {other:?}"),
            }
        };
        (stdout_bytes, stderr_bytes, stdout_eof, stderr_eof, exit_msg)
    }

    fn make_raw_tar_with_entry(
        path: &str,
        entry_type: tar::EntryType,
        data: &[u8],
        linkname: Option<&str>,
    ) -> Vec<u8> {
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(entry_type);
        header.set_size(data.len() as u64);
        header.set_mode(0o644);

        let mut buf = Vec::new();
        if let Some(target) = linkname {
            let mut builder = tar::Builder::new(&mut buf);
            builder
                .append_link(&mut header, path, target)
                .expect("append link entry");
            builder.finish().unwrap();
        } else {
            // Write raw header bytes directly so even `..` or absolute paths bypass tar::Builder checks.
            let path_bytes = path.as_bytes();
            let raw = header.as_mut_bytes();
            let copy_len = path_bytes.len().min(100);
            raw[..copy_len].copy_from_slice(&path_bytes[..copy_len]);
            header.set_cksum();
            buf.extend_from_slice(header.as_bytes());
            if !data.is_empty() {
                buf.extend_from_slice(data);
                let rem = data.len() % 512;
                if rem != 0 {
                    buf.resize(buf.len() + (512 - rem), 0);
                }
            }
            buf.extend_from_slice(&[0u8; 1024]);
        }
        buf
    }

    fn send_copy_in(
        host_tx: &mut ChannelWriter,
        host_rx: &mut ChannelReader,
        stream_id: StreamId,
        dst_guest: &str,
        max_bytes: u64,
        tar_bytes: &[u8],
        chunk_size: usize,
    ) -> Message {
        send_message(
            host_tx,
            stream_id,
            &Message::CopyInStart {
                dst_guest: dst_guest.to_owned(),
                max_bytes,
            },
        )
        .unwrap();

        if tar_bytes.is_empty() {
            send_message(
                host_tx,
                stream_id,
                &Message::StreamData {
                    channel: StreamChannel::Stdin,
                    eof: true,
                    data: Vec::new(),
                },
            )
            .unwrap();
        } else {
            let mut chunks = tar_bytes.chunks(chunk_size.max(1)).peekable();
            while let Some(chunk) = chunks.next() {
                let eof = chunks.peek().is_none();
                send_message(
                    host_tx,
                    stream_id,
                    &Message::StreamData {
                        channel: StreamChannel::Stdin,
                        eof,
                        data: chunk.to_vec(),
                    },
                )
                .unwrap();
            }
        }

        loop {
            let frame = read_frame(host_rx).expect("copy_in reply frame");
            assert_eq!(frame.header.stream_id, stream_id);
            match frame.decode_message().unwrap() {
                Message::StreamCredit {
                    channel: StreamChannel::Stdin,
                    ..
                } => continue,
                msg @ (Message::CopyDone { .. } | Message::CopyError { .. }) => return msg,
                other => panic!("unexpected frame during copy_in: {other:?}"),
            }
        }
    }

    fn shutdown_test_session(
        mut host_rx: ChannelReader,
        mut host_tx: ChannelWriter,
        agent: thread::JoinHandle<Result<(), ProtocolError>>,
    ) {
        send_message(&mut host_tx, StreamId(0), &Message::Shutdown).unwrap();
        let ack = read_frame(&mut host_rx).unwrap();
        assert_eq!(ack.header.stream_id, StreamId(0));
        assert_eq!(ack.decode_message().unwrap(), Message::Shutdown);
        drop(host_tx);
        agent.join().expect("agent thread did not panic").unwrap();
    }

    #[test]
    fn interactive_session_handles_handshake_ping_exec_and_shutdown() {
        let (mut host_rx, mut host_tx, agent) = start_test_session();

        // Ping / Pong preserves arbitrary StreamId.
        send_message(&mut host_tx, StreamId(9), &Message::Ping { seq: 1234 }).unwrap();
        let pong = read_frame(&mut host_rx).expect("Pong expected");
        assert_eq!(pong.header.stream_id, StreamId(9));
        assert_eq!(pong.decode_message().unwrap(), Message::Pong { seq: 1234 });

        // ExecStart runs a real command producing stdout, stderr, and non-zero exit code.
        #[cfg(windows)]
        let script = "echo hello-out& echo hello-err 1>&2& exit /b 7";
        #[cfg(unix)]
        let script = "printf 'hello-out\\n'; printf 'hello-err\\n' >&2; exit 7";

        send_message(&mut host_tx, StreamId(11), &guest_exec_start(shell_cmd(script))).unwrap();

        let (stdout_bytes, stderr_bytes, stdout_eof, stderr_eof, exit_msg) =
            collect_exec_response(&mut host_rx, StreamId(11));
        assert!(stdout_eof && stderr_eof);
        assert_eq!(
            exit_msg,
            Message::ExecExit {
                code: Some(7),
                timed_out: false,
                stdout_truncated: false,
                stderr_truncated: false,
            }
        );
        assert!(
            String::from_utf8_lossy(&stdout_bytes).contains("hello-out"),
            "stdout was {:?}",
            String::from_utf8_lossy(&stdout_bytes)
        );
        assert!(
            String::from_utf8_lossy(&stderr_bytes).contains("hello-err"),
            "stderr was {:?}",
            String::from_utf8_lossy(&stderr_bytes)
        );

        // Missing binary reports error on stderr and exit code 127.
        send_message(
            &mut host_tx,
            StreamId(12),
            &guest_exec_start(vec!["minipod_nonexistent_binary_99999".to_owned()]),
        )
        .unwrap();

        let f_out = read_frame(&mut host_rx).unwrap();
        assert_eq!(f_out.header.stream_id, StreamId(12));
        assert_eq!(
            f_out.decode_message().unwrap(),
            Message::StreamData {
                channel: StreamChannel::Stdout,
                eof: true,
                data: Vec::new(),
            }
        );

        let f_err = read_frame(&mut host_rx).unwrap();
        assert_eq!(f_err.header.stream_id, StreamId(12));
        match f_err.decode_message().unwrap() {
            Message::StreamData {
                channel: StreamChannel::Stderr,
                eof: true,
                data,
            } => {
                assert!(!data.is_empty(), "expected spawn failure message on stderr");
            }
            other => panic!("expected stderr frame, got {other:?}"),
        }

        let f_exit = read_frame(&mut host_rx).unwrap();
        assert_eq!(f_exit.header.stream_id, StreamId(12));
        assert_eq!(
            f_exit.decode_message().unwrap(),
            Message::ExecExit {
                code: Some(127),
                timed_out: false,
                stdout_truncated: false,
                stderr_truncated: false,
            }
        );

        shutdown_test_session(host_rx, host_tx, agent);
    }

    #[test]
    fn handshake_rejects_mismatched_version_and_non_ack() {
        let bad_ver = encode_frames(&[(
            StreamId(0),
            Message::HelloAck {
                version: PROTOCOL_VERSION + 1,
                features: 0,
            },
        )]);
        let mut reader = Cursor::new(bad_ver);
        let mut writer = Vec::new();
        assert_eq!(
            serve_session(&mut reader, &mut writer),
            Err(ProtocolError::UnsupportedVersion(PROTOCOL_VERSION + 1))
        );

        let wrong_msg = encode_frames(&[(StreamId(0), Message::Ping { seq: 1 })]);
        let mut reader = Cursor::new(wrong_msg);
        let mut writer = Vec::new();
        assert!(matches!(
            serve_session(&mut reader, &mut writer),
            Err(ProtocolError::InvalidPayload(_))
        ));
    }

    #[test]
    fn clean_eof_after_handshake_exits_ok() {
        let input = encode_frames(&[(
            StreamId(0),
            Message::HelloAck {
                version: PROTOCOL_VERSION,
                features: 0,
            },
        )]);
        let mut reader = Cursor::new(input);
        let mut writer = Vec::new();
        serve_session(&mut reader, &mut writer).expect("clean EOF should return Ok(())");

        let mut out_cursor = Cursor::new(writer);
        let hello = read_frame(&mut out_cursor).unwrap();
        assert_eq!(
            hello.decode_message().unwrap(),
            Message::Hello {
                version: PROTOCOL_VERSION
            }
        );
        assert_eq!(read_frame(&mut out_cursor), Err(ProtocolError::Eof));
    }

    #[test]
    fn outbound_queue_chunks_large_stream_within_frame_limit() {
        let payload = vec![b'x'; MAX_STREAM_DATA_CHUNK_BYTES + 17];
        let outbound = OutboundQueue::new();
        outbound
            .send_stream_data_final(StreamId(5), StreamChannel::Stdout, &payload)
            .expect("chunking must fit within MAX_FRAME_PAYLOAD_BYTES");
        outbound.finish_and_drain();

        let mut wire = Vec::new();
        while let Some(frame) = outbound.pop_for_writer() {
            write_frame(&mut wire, &frame).unwrap();
        }

        let mut cursor = Cursor::new(wire);
        let first = read_frame(&mut cursor).unwrap();
        assert_eq!(first.header.stream_id, StreamId(5));
        assert_eq!(
            first.decode_message().unwrap(),
            Message::StreamData {
                channel: StreamChannel::Stdout,
                eof: false,
                data: vec![b'x'; MAX_STREAM_DATA_CHUNK_BYTES],
            }
        );

        let second = read_frame(&mut cursor).unwrap();
        assert_eq!(second.header.stream_id, StreamId(5));
        assert_eq!(
            second.decode_message().unwrap(),
            Message::StreamData {
                channel: StreamChannel::Stdout,
                eof: true,
                data: vec![b'x'; 17],
            }
        );

        assert_eq!(read_frame(&mut cursor), Err(ProtocolError::Eof));
    }

    #[test]
    fn exec_rejects_container_target_and_invalid_user_without_killing_session() {
        let (mut host_rx, mut host_tx, agent) = start_test_session();

        send_message(
            &mut host_tx,
            StreamId(1),
            &Message::ExecStart {
                target: ExecTargetWire::Container {
                    id_or_name: "-bad-container".to_owned(),
                },
                argv: vec!["/bin/true".to_owned()],
                env: BTreeMap::new(),
                cwd: None,
                user: None,
                deadline_ms: 5_000,
                stdout_budget_bytes: 4096,
                stderr_budget_bytes: 4096,
            },
        )
        .unwrap();

        let (_, stderr_c, stdout_eof_c, stderr_eof_c, exit_c) =
            collect_exec_response(&mut host_rx, StreamId(1));
        assert!(stdout_eof_c && stderr_eof_c);
        assert!(matches!(exit_c, Message::ExecExit { code: Some(125), .. }));
        assert!(String::from_utf8_lossy(&stderr_c).contains("must not start with '-'"));

        send_message(
            &mut host_tx,
            StreamId(2),
            &Message::ExecStart {
                target: ExecTargetWire::Guest,
                argv: vec!["/bin/true".to_owned()],
                env: BTreeMap::new(),
                cwd: None,
                user: Some("minipod_missing_user_99999".to_owned()),
                deadline_ms: 5_000,
                stdout_budget_bytes: 4096,
                stderr_budget_bytes: 4096,
            },
        )
        .unwrap();

        let (_, stderr_u, stdout_eof_u, stderr_eof_u, exit_u) =
            collect_exec_response(&mut host_rx, StreamId(2));
        assert!(stdout_eof_u && stderr_eof_u);
        assert!(matches!(exit_u, Message::ExecExit { code: Some(126), .. }));
        assert!(!stderr_u.is_empty());

        // Session must remain healthy after diagnostic rejections.
        send_message(&mut host_tx, StreamId(0), &Message::Ping { seq: 55 }).unwrap();
        let pong = read_frame(&mut host_rx).unwrap();
        assert_eq!(pong.decode_message().unwrap(), Message::Pong { seq: 55 });

        shutdown_test_session(host_rx, host_tx, agent);
    }

    #[test]
    fn exec_streams_stdin_stdout_and_enforces_env_and_cwd() {
        let tmp = TestTempDir::new("exec-io");
        let (mut host_rx, mut host_tx, agent) = start_test_session();

        #[cfg(windows)]
        let argv = vec![
            "cmd".to_owned(),
            "/V:ON".to_owned(),
            "/C".to_owned(),
            "set /p line= & echo !line!-%MINIPOD_TAG% & cd".to_owned(),
        ];
        #[cfg(unix)]
        let argv = shell_cmd("IFS= read -r line; printf '%s-%s\\n' \"$line\" \"$MINIPOD_TAG\"; pwd");

        let mut env = BTreeMap::new();
        env.insert("MINIPOD_TAG".to_owned(), "ok42".to_owned());

        send_message(
            &mut host_tx,
            StreamId(3),
            &Message::ExecStart {
                target: ExecTargetWire::Guest,
                argv,
                env,
                cwd: Some(tmp.path().to_string_lossy().into_owned()),
                user: None,
                deadline_ms: 15_000,
                stdout_budget_bytes: 65_536,
                stderr_budget_bytes: 65_536,
            },
        )
        .unwrap();

        send_message(
            &mut host_tx,
            StreamId(3),
            &Message::StreamData {
                channel: StreamChannel::Stdin,
                eof: false,
                data: b"hello".to_vec(),
            },
        )
        .unwrap();
        send_message(
            &mut host_tx,
            StreamId(3),
            &Message::StreamData {
                channel: StreamChannel::Stdin,
                eof: true,
                data: b"\n".to_vec(),
            },
        )
        .unwrap();

        let mut stdout_bytes = Vec::new();
        let mut saw_exit = None;
        while saw_exit.is_none() {
            let frame = read_frame(&mut host_rx).unwrap();
            assert_eq!(frame.header.stream_id, StreamId(3));
            match frame.decode_message().unwrap() {
                Message::StreamData {
                    channel: StreamChannel::Stdout,
                    data,
                    ..
                } => stdout_bytes.extend_from_slice(&data),
                Message::StreamData {
                    channel: StreamChannel::Stderr,
                    ..
                }
                | Message::StreamCredit {
                    channel: StreamChannel::Stdin,
                    ..
                } => {}
                msg @ Message::ExecExit { .. } => saw_exit = Some(msg),
                other => panic!("unexpected frame: {other:?}"),
            }
        }
        assert_eq!(
            saw_exit.unwrap(),
            Message::ExecExit {
                code: Some(0),
                timed_out: false,
                stdout_truncated: false,
                stderr_truncated: false,
            }
        );
        let out_str = String::from_utf8_lossy(&stdout_bytes);
        assert!(out_str.contains("hello") && out_str.contains("ok42"), "stdout: {out_str:?}");
        assert!(
            out_str.contains(&tmp.path().file_name().unwrap().to_string_lossy().to_string()),
            "expected cwd in stdout: {out_str:?}"
        );

        shutdown_test_session(host_rx, host_tx, agent);
    }

    #[test]
    fn exec_budget_overflow_truncates_kills_and_reports_flags() {
        let (mut host_rx, mut host_tx, agent) = start_test_session();

        #[cfg(windows)]
        let script = "for /L %i in (1,1,500) do @echo 0123456789abcdef0123456789abcdef";
        #[cfg(unix)]
        let script = "i=0; while [ $i -lt 500 ]; do printf '0123456789abcdef0123456789abcdef\\n'; i=$((i+1)); done";

        send_message(
            &mut host_tx,
            StreamId(4),
            &Message::ExecStart {
                target: ExecTargetWire::Guest,
                argv: shell_cmd(script),
                env: BTreeMap::new(),
                cwd: None,
                user: None,
                deadline_ms: 15_000,
                stdout_budget_bytes: 120,
                stderr_budget_bytes: 4096,
            },
        )
        .unwrap();

        let (stdout_bytes, _stderr_bytes, stdout_eof, stderr_eof, exit_msg) =
            collect_exec_response(&mut host_rx, StreamId(4));
        assert!(stdout_eof && stderr_eof);
        assert_eq!(stdout_bytes.len(), 120, "forwarded bytes must be capped at exact budget");
        assert_eq!(
            exit_msg,
            Message::ExecExit {
                code: None,
                timed_out: false,
                stdout_truncated: true,
                stderr_truncated: false,
            }
        );

        shutdown_test_session(host_rx, host_tx, agent);
    }

    #[test]
    fn exec_deadline_and_cancel_kill_running_process_and_keep_ping_responsive() {
        let (mut host_rx, mut host_tx, agent) = start_test_session();

        // 1. Deadline timeout test.
        #[cfg(windows)]
        let slow_argv = vec![
            "ping".to_owned(),
            "-n".to_owned(),
            "10".to_owned(),
            "127.0.0.1".to_owned(),
        ];
        #[cfg(unix)]
        let slow_argv = shell_cmd("sleep 10");

        send_message(
            &mut host_tx,
            StreamId(5),
            &Message::ExecStart {
                target: ExecTargetWire::Guest,
                argv: slow_argv.clone(),
                env: BTreeMap::new(),
                cwd: None,
                user: None,
                deadline_ms: 150,
                stdout_budget_bytes: 4096,
                stderr_budget_bytes: 4096,
            },
        )
        .unwrap();

        let (_, _, stdout_eof, stderr_eof, exit_timeout) =
            collect_exec_response(&mut host_rx, StreamId(5));
        assert!(stdout_eof && stderr_eof);
        assert_eq!(
            exit_timeout,
            Message::ExecExit {
                code: None,
                timed_out: true,
                stdout_truncated: false,
                stderr_truncated: false,
            }
        );

        // 2. Concurrent Ping + ExecCancel test.
        send_message(
            &mut host_tx,
            StreamId(6),
            &Message::ExecStart {
                target: ExecTargetWire::Guest,
                argv: slow_argv,
                env: BTreeMap::new(),
                cwd: None,
                user: None,
                deadline_ms: 30_000,
                stdout_budget_bytes: 4096,
                stderr_budget_bytes: 4096,
            },
        )
        .unwrap();

        send_message(&mut host_tx, StreamId(0), &Message::Ping { seq: 777 }).unwrap();
        let mut got_pong = false;
        let mut cancel_sent = false;
        let mut got_cancel_exit = None;

        while got_cancel_exit.is_none() || !got_pong {
            if !cancel_sent && got_pong {
                send_message(&mut host_tx, StreamId(6), &Message::ExecCancel).unwrap();
                cancel_sent = true;
            }
            let frame = read_frame(&mut host_rx).unwrap();
            match frame.decode_message().unwrap() {
                Message::Pong { seq: 777 } => {
                    assert_eq!(frame.header.stream_id, StreamId(0));
                    got_pong = true;
                }
                Message::StreamData { .. } => {}
                msg @ Message::ExecExit { .. } => {
                    assert_eq!(frame.header.stream_id, StreamId(6));
                    got_cancel_exit = Some(msg);
                }
                other => panic!("unexpected frame: {other:?}"),
            }
        }
        assert_eq!(
            got_cancel_exit.unwrap(),
            Message::ExecExit {
                code: None,
                timed_out: false,
                stdout_truncated: false,
                stderr_truncated: false,
            }
        );

        shutdown_test_session(host_rx, host_tx, agent);
    }

    #[cfg(unix)]
    #[test]
    fn unix_process_group_kill_terminates_orphan_grandchild() {
        let tmp = TestTempDir::new("pgid-kill");
        let pid_file = tmp.path().join("grandchild.pid");
        let (mut host_rx, mut host_tx, agent) = start_test_session();

        let script = format!(
            "sleep 30 & echo $! > '{}'; wait",
            pid_file.display()
        );
        send_message(
            &mut host_tx,
            StreamId(20),
            &Message::ExecStart {
                target: ExecTargetWire::Guest,
                argv: vec!["/bin/sh".to_owned(), "-c".to_owned(), script],
                env: BTreeMap::new(),
                cwd: None,
                user: None,
                deadline_ms: 30_000,
                stdout_budget_bytes: 4096,
                stderr_budget_bytes: 4096,
            },
        )
        .unwrap();

        let wait_deadline = Instant::now() + Duration::from_secs(5);
        let grandchild_pid: i32 = loop {
            if let Ok(raw) = fs::read_to_string(&pid_file) {
                if let Ok(pid) = raw.trim().parse::<i32>() {
                    break pid;
                }
            }
            assert!(Instant::now() < wait_deadline, "grandchild did not write pid file in time");
            thread::sleep(Duration::from_millis(20));
        };
        #[cfg(not(target_os = "linux"))]
        let _ = grandchild_pid;

        let start = Instant::now();
        send_message(&mut host_tx, StreamId(20), &Message::ExecCancel).unwrap();
        let (_, _, stdout_eof, stderr_eof, exit_msg) =
            collect_exec_response(&mut host_rx, StreamId(20));
        assert!(stdout_eof && stderr_eof);
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "process-group kill must close grandchild pipes immediately without waiting 30s"
        );
        assert_eq!(
            exit_msg,
            Message::ExecExit {
                code: None,
                timed_out: false,
                stdout_truncated: false,
                stderr_truncated: false,
            }
        );

        #[cfg(target_os = "linux")]
        {
            let is_running = |pid: i32| -> bool {
                let Ok(status) = fs::read_to_string(format!("/proc/{pid}/status")) else {
                    return false;
                };
                for line in status.lines() {
                    if let Some(rest) = line.strip_prefix("State:") {
                        return !rest.trim_start().starts_with('Z');
                    }
                }
                true
            };
            let reap_deadline = Instant::now() + Duration::from_secs(2);
            while is_running(grandchild_pid) && Instant::now() < reap_deadline {
                thread::sleep(Duration::from_millis(10));
            }
            assert!(
                !is_running(grandchild_pid),
                "orphan grandchild PID {grandchild_pid} must be terminated (not running) after process-group kill"
            );
        }

        shutdown_test_session(host_rx, host_tx, agent);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_exec_scope_kills_setsid_detached_child_on_deadline() {
        let tmp = TestTempDir::new("setsid-kill");
        let pid_file = tmp.path().join("setsid.pid");
        let marker_file = tmp.path().join("escaped.marker");
        let (mut host_rx, mut host_tx, agent) = start_test_session();

        let script = format!(
            "setsid sh -c 'sleep 1; echo survived > \"{}\"' </dev/null >/dev/null 2>&1 & echo $! > '{}'; wait",
            marker_file.display(),
            pid_file.display(),
        );
        send_message(
            &mut host_tx,
            StreamId(21),
            &Message::ExecStart {
                target: ExecTargetWire::Guest,
                argv: vec!["/bin/sh".to_owned(), "-c".to_owned(), script],
                env: BTreeMap::new(),
                cwd: None,
                user: None,
                deadline_ms: 250,
                stdout_budget_bytes: 4096,
                stderr_budget_bytes: 4096,
            },
        )
        .unwrap();

        let (_, _, stdout_eof, stderr_eof, exit_msg) =
            collect_exec_response(&mut host_rx, StreamId(21));
        assert!(stdout_eof && stderr_eof);
        assert_eq!(
            exit_msg,
            Message::ExecExit {
                code: None,
                timed_out: true,
                stdout_truncated: false,
                stderr_truncated: false,
            }
        );

        let detached_pid: i32 = fs::read_to_string(&pid_file)
            .expect("setsid child wrote pid before 250ms deadline")
            .trim()
            .parse()
            .unwrap();
        let is_running = |pid: i32| -> bool {
            let Ok(status) = fs::read_to_string(format!("/proc/{pid}/status")) else {
                return false;
            };
            for line in status.lines() {
                if let Some(rest) = line.strip_prefix("State:") {
                    return !rest.trim_start().starts_with('Z');
                }
            }
            true
        };
        assert!(
            !is_running(detached_pid),
            "setsid detached PID {detached_pid} must be dead before ExecExit is reported"
        );

        thread::sleep(Duration::from_millis(1200));
        assert!(
            !marker_file.exists(),
            "detached setsid child must not write marker after deadline"
        );

        shutdown_test_session(host_rx, host_tx, agent);
    }

    #[test]
    fn stream_credit_enforces_stdout_backpressure() {
        let (mut host_rx, mut host_tx, agent) = start_test_session();

        // Opt into credit flow control for StreamId(30) Stdout with 10 bytes initially.
        send_message(
            &mut host_tx,
            StreamId(30),
            &Message::StreamCredit {
                channel: StreamChannel::Stdout,
                bytes: 10,
            },
        )
        .unwrap();

        #[cfg(windows)]
        let script = "echo 0123456789abcdefghij";
        #[cfg(unix)]
        let script = "printf '0123456789abcdefghij'";

        send_message(&mut host_tx, StreamId(30), &guest_exec_start(shell_cmd(script))).unwrap();

        // First chunk must be capped at 10 bytes while remaining bytes wait for credit.
        // Stderr EOF may arrive concurrently before stdout is flushed.
        let mut pre_stderr_eof = false;
        let first = loop {
            let f = read_frame(&mut host_rx).unwrap();
            assert_eq!(f.header.stream_id, StreamId(30));
            match f.decode_message().unwrap() {
                Message::StreamData {
                    channel: StreamChannel::Stdout,
                    eof,
                    data,
                } => {
                    assert!(!eof);
                    assert_eq!(data.len(), 10);
                    break data;
                }
                Message::StreamData {
                    channel: StreamChannel::Stderr,
                    eof,
                    data,
                } => {
                    assert!(data.is_empty(), "unexpected stderr output: {data:?}");
                    if eof {
                        pre_stderr_eof = true;
                    }
                }
                other => panic!("unexpected frame while waiting for capped stdout: {other:?}"),
            }
        };

        // Grant remaining credit and verify full stdout arrives followed by ExecExit.
        send_message(
            &mut host_tx,
            StreamId(30),
            &Message::StreamCredit {
                channel: StreamChannel::Stdout,
                bytes: 1024,
            },
        )
        .unwrap();

        let (rest_stdout, stderr_rest, stdout_eof, stderr_eof, exit_msg) =
            collect_exec_response(&mut host_rx, StreamId(30));
        assert!(stderr_rest.is_empty(), "unexpected stderr: {stderr_rest:?}");
        assert!(stdout_eof && (pre_stderr_eof || stderr_eof));
        assert!(matches!(exit_msg, Message::ExecExit { code: Some(0), .. }));

        let mut all = first;
        all.extend_from_slice(&rest_stdout);
        let text = String::from_utf8_lossy(&all);
        assert!(text.contains("0123456789abcdefghij"), "stdout was {text:?}");

        shutdown_test_session(host_rx, host_tx, agent);
    }

    #[test]
    fn user_resolution_parses_numeric_and_passwd_tables() {
        let passwd = "root:x:0:0:root:/root:/bin/sh\nalice:x:1000:1001:Alice:/home/alice:/bin/sh\n";
        let group = "root:x:0:\ndevs:x:2000:alice\n";

        assert_eq!(
            supervisor::resolve_user_ids_from_tables("0", Some(passwd), Some(group)),
            Ok((0, 0))
        );
        assert_eq!(
            supervisor::resolve_user_ids_from_tables("1000", Some(passwd), Some(group)),
            Ok((1000, 1001))
        );
        assert_eq!(
            supervisor::resolve_user_ids_from_tables("1000:2000", Some(passwd), Some(group)),
            Ok((1000, 2000))
        );
        assert_eq!(
            supervisor::resolve_user_ids_from_tables("alice", Some(passwd), Some(group)),
            Ok((1000, 1001))
        );
        assert_eq!(
            supervisor::resolve_user_ids_from_tables("alice:devs", Some(passwd), Some(group)),
            Ok((1000, 2000))
        );
        assert!(supervisor::resolve_user_ids_from_tables("bob", Some(passwd), Some(group)).is_err());
        assert!(supervisor::resolve_user_ids_from_tables("alice:nope", Some(passwd), Some(group)).is_err());
        assert!(supervisor::resolve_user_ids_from_tables("1000:2000:3000", Some(passwd), Some(group)).is_err());
        assert!(supervisor::resolve_user_ids_from_tables("", Some(passwd), Some(group)).is_err());
    }

    #[test]
    fn copy_in_and_copy_out_roundtrip_and_security_rejections() {
        let tmp = TestTempDir::new("copy-tar");
        let src_dir = tmp.path().join("src");
        let sub_dir = src_dir.join("nested");
        fs::create_dir_all(&sub_dir).unwrap();
        fs::write(src_dir.join("hello.txt"), b"hello-tar-world").unwrap();
        fs::write(sub_dir.join("data.bin"), vec![0xABu8; 70_000]).unwrap();

        let (mut host_rx, mut host_tx, agent) = start_test_session();

        // 1. CopyOutStart streams multi-chunk tar archive followed strictly by CopyDone.
        send_message(
            &mut host_tx,
            StreamId(40),
            &Message::CopyOutStart {
                src_guest: src_dir.to_string_lossy().into_owned(),
                max_bytes: 1_048_576,
            },
        )
        .unwrap();

        let mut tar_out = Vec::new();
        let mut saw_eof = false;
        let bytes_transferred = loop {
            let frame = read_frame(&mut host_rx).unwrap();
            assert_eq!(frame.header.stream_id, StreamId(40));
            match frame.decode_message().unwrap() {
                Message::StreamData {
                    channel: StreamChannel::Stdout,
                    eof,
                    data,
                } => {
                    assert!(!saw_eof, "no StreamData may follow eof: true");
                    tar_out.extend_from_slice(&data);
                    if eof {
                        saw_eof = true;
                    }
                }
                Message::CopyDone { bytes_transferred } => {
                    assert!(saw_eof, "CopyDone must strictly follow StreamData eof: true");
                    break bytes_transferred;
                }
                other => panic!("unexpected copy_out frame: {other:?}"),
            }
        };
        assert_eq!(bytes_transferred as usize, tar_out.len());
        assert!(tar_out.len() > 65_536, "expected multi-chunk tar output");

        // 2. CopyInStart unpacks that tar archive cleanly into a new destination directory.
        let dst_dir = tmp.path().join("dst").join("unpacked");
        let reply = send_copy_in(
            &mut host_tx,
            &mut host_rx,
            StreamId(41),
            &dst_dir.to_string_lossy(),
            1_048_576,
            &tar_out,
            16_384,
        );
        assert_eq!(
            reply,
            Message::CopyDone {
                bytes_transferred: tar_out.len() as u64
            }
        );
        assert_eq!(fs::read(dst_dir.join("hello.txt")).unwrap(), b"hello-tar-world");
        assert_eq!(
            fs::read(dst_dir.join("nested").join("data.bin")).unwrap(),
            vec![0xABu8; 70_000]
        );

        // 3. CopyOutStart rejects max_bytes overflow.
        send_message(
            &mut host_tx,
            StreamId(42),
            &Message::CopyOutStart {
                src_guest: src_dir.to_string_lossy().into_owned(),
                max_bytes: 1024,
            },
        )
        .unwrap();
        let err_frame = read_frame(&mut host_rx).unwrap();
        assert_eq!(err_frame.header.stream_id, StreamId(42));
        assert!(matches!(
            err_frame.decode_message().unwrap(),
            Message::CopyError { .. }
        ));

        // 4. CopyInStart rejects `..`, absolute path, symlink, hardlink, FIFO, and max_bytes overflow.
        let evil_dst = tmp.path().join("evil-dst");
        let traversal_tar =
            make_raw_tar_with_entry("../escape.txt", tar::EntryType::Regular, b"pwn", None);
        assert!(matches!(
            send_copy_in(
                &mut host_tx,
                &mut host_rx,
                StreamId(43),
                &evil_dst.to_string_lossy(),
                65_536,
                &traversal_tar,
                65_536,
            ),
            Message::CopyError { .. }
        ));
        assert!(!tmp.path().join("escape.txt").exists());

        let abs_tar =
            make_raw_tar_with_entry("/etc/shadow_test", tar::EntryType::Regular, b"pwn", None);
        assert!(matches!(
            send_copy_in(
                &mut host_tx,
                &mut host_rx,
                StreamId(44),
                &evil_dst.to_string_lossy(),
                65_536,
                &abs_tar,
                65_536,
            ),
            Message::CopyError { .. }
        ));

        let symlink_tar =
            make_raw_tar_with_entry("sym", tar::EntryType::Symlink, &[], Some("/etc/passwd"));
        assert!(matches!(
            send_copy_in(
                &mut host_tx,
                &mut host_rx,
                StreamId(45),
                &evil_dst.to_string_lossy(),
                65_536,
                &symlink_tar,
                65_536,
            ),
            Message::CopyError { .. }
        ));

        let hardlink_tar =
            make_raw_tar_with_entry("hard", tar::EntryType::Link, &[], Some("target"));
        assert!(matches!(
            send_copy_in(
                &mut host_tx,
                &mut host_rx,
                StreamId(46),
                &evil_dst.to_string_lossy(),
                65_536,
                &hardlink_tar,
                65_536,
            ),
            Message::CopyError { .. }
        ));

        let fifo_tar = make_raw_tar_with_entry("pipe", tar::EntryType::Fifo, &[], None);
        assert!(matches!(
            send_copy_in(
                &mut host_tx,
                &mut host_rx,
                StreamId(47),
                &evil_dst.to_string_lossy(),
                65_536,
                &fifo_tar,
                65_536,
            ),
            Message::CopyError { .. }
        ));

        // 5. CopyInStart rejects max_bytes overflow, relative paths, and '..' dst_guest cleanly.
        assert!(matches!(
            send_copy_in(
                &mut host_tx,
                &mut host_rx,
                StreamId(48),
                &evil_dst.to_string_lossy(),
                512,
                &tar_out,
                1024,
            ),
            Message::CopyError { .. }
        ));
        assert!(matches!(
            send_copy_in(
                &mut host_tx,
                &mut host_rx,
                StreamId(49),
                "relative/dst",
                65_536,
                &make_raw_tar_with_entry("ok.txt", tar::EntryType::Regular, b"hi", None),
                65_536,
            ),
            Message::CopyError { .. }
        ));

        // 6. Single-file CopyOutStart packs basename cleanly.
        let single_file = src_dir.join("hello.txt");
        send_message(
            &mut host_tx,
            StreamId(50),
            &Message::CopyOutStart {
                src_guest: single_file.to_string_lossy().into_owned(),
                max_bytes: 65_536,
            },
        )
        .unwrap();
        let mut single_tar = Vec::new();
        loop {
            let f = read_frame(&mut host_rx).unwrap();
            match f.decode_message().unwrap() {
                Message::StreamData { data, .. } => single_tar.extend_from_slice(&data),
                Message::CopyDone { .. } => break,
                other => panic!("unexpected single-file copy_out frame: {other:?}"),
            }
        }
        let single_dst = tmp.path().join("single-dst");
        assert!(matches!(
            send_copy_in(
                &mut host_tx,
                &mut host_rx,
                StreamId(51),
                &single_dst.to_string_lossy(),
                65_536,
                &single_tar,
                65_536,
            ),
            Message::CopyDone { .. }
        ));
        assert_eq!(fs::read(single_dst.join("hello.txt")).unwrap(), b"hello-tar-world");

        shutdown_test_session(host_rx, host_tx, agent);
    }

    #[cfg(unix)]
    #[test]
    fn unix_copy_tar_rejects_existing_symlink_traversal() {
        use std::os::unix::fs::symlink;

        let tmp = TestTempDir::new("unix-symlink");
        let outside = tmp.path().join("outside");
        let root = tmp.path().join("root");
        fs::create_dir_all(&outside).unwrap();
        fs::create_dir_all(&root).unwrap();
        let sym_link = root.join("link");
        symlink(&outside, &sym_link).unwrap();

        let (mut host_rx, mut host_tx, agent) = start_test_session();

        let good_tar =
            make_raw_tar_with_entry("pwned.txt", tar::EntryType::Regular, b"nope", None);
        let reply_in = send_copy_in(
            &mut host_tx,
            &mut host_rx,
            StreamId(50),
            &sym_link.join("sub").to_string_lossy(),
            65_536,
            &good_tar,
            65_536,
        );
        assert!(matches!(reply_in, Message::CopyError { .. }));
        assert!(!outside.join("sub").exists());

        send_message(
            &mut host_tx,
            StreamId(51),
            &Message::CopyOutStart {
                src_guest: root.to_string_lossy().into_owned(),
                max_bytes: 65_536,
            },
        )
        .unwrap();
        let err_frame = read_frame(&mut host_rx).unwrap();
        assert!(matches!(
            err_frame.decode_message().unwrap(),
            Message::CopyError { .. }
        ));

        shutdown_test_session(host_rx, host_tx, agent);
    }

    #[test]
    fn exec_stderr_budget_overflow_truncates_and_kills() {
        let (mut host_rx, mut host_tx, agent) = start_test_session();

        #[cfg(windows)]
        let script = "for /L %i in (1,1,500) do @echo err0123456789abcdef0123456789 1>&2";
        #[cfg(unix)]
        let script = "i=0; while [ $i -lt 500 ]; do printf 'err0123456789abcdef0123456789\\n' >&2; i=$((i+1)); done";

        send_message(
            &mut host_tx,
            StreamId(14),
            &Message::ExecStart {
                target: ExecTargetWire::Guest,
                argv: shell_cmd(script),
                env: BTreeMap::new(),
                cwd: None,
                user: None,
                deadline_ms: 15_000,
                stdout_budget_bytes: 4096,
                stderr_budget_bytes: 64,
            },
        )
        .unwrap();

        let (_stdout_bytes, stderr_bytes, stdout_eof, stderr_eof, exit_msg) =
            collect_exec_response(&mut host_rx, StreamId(14));
        assert!(stdout_eof && stderr_eof);
        assert_eq!(stderr_bytes.len(), 64);
        assert_eq!(
            exit_msg,
            Message::ExecExit {
                code: None,
                timed_out: false,
                stdout_truncated: false,
                stderr_truncated: true,
            }
        );

        shutdown_test_session(host_rx, host_tx, agent);
    }

    #[test]
    fn outbound_queue_preempts_data_with_control_and_holds_exec_exit_until_drained() {
        let outbound = OutboundQueue::new();
        outbound
            .send_stream_data(StreamId(1), StreamChannel::Stdout, b"chunk-1")
            .unwrap();
        outbound.send_stream_eof(StreamId(1), StreamChannel::Stdout).unwrap();
        outbound
            .push_message(StreamId(0), &Message::Pong { seq: 99 })
            .unwrap();

        let outbound_bg = Arc::new(outbound);
        let outbound_waiter = outbound_bg.clone();
        let exit_enqueuer = thread::spawn(move || {
            outbound_waiter
                .enqueue_exec_exit_after_data(
                    StreamId(1),
                    &Message::ExecExit {
                        code: Some(0),
                        timed_out: false,
                        stdout_truncated: false,
                        stderr_truncated: false,
                    },
                )
                .unwrap();
        });

        // 1. Control Pong must dequeue before Data frames.
        let first = outbound_bg.pop_for_writer().unwrap();
        assert_eq!(first.decode_message().unwrap(), Message::Pong { seq: 99 });

        // 2. Drain Data frames for StreamId(1); ExecExit cannot overtake them.
        let d1 = outbound_bg.pop_for_writer().unwrap();
        assert!(matches!(
            d1.decode_message().unwrap(),
            Message::StreamData { eof: false, .. }
        ));
        let d2 = outbound_bg.pop_for_writer().unwrap();
        assert!(matches!(
            d2.decode_message().unwrap(),
            Message::StreamData { eof: true, .. }
        ));

        // 3. Only after Data frames drained does ExecExit arrive.
        exit_enqueuer.join().unwrap();
        let exit = outbound_bg.pop_for_writer().unwrap();
        assert!(matches!(exit.decode_message().unwrap(), Message::ExecExit { .. }));
        outbound_bg.finish_and_drain();
        assert!(outbound_bg.pop_for_writer().is_none());
    }

    #[test]
    fn serve_session_relays_loopback_tcp_tunnel_and_rejects_invalid_connect() {
        use sandbox_protocol::StreamTargetWire;
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            let mut req = Vec::new();
            conn.read_to_end(&mut req).unwrap();
            assert_eq!(req, b"hello-tunnel");
            conn.write_all(b"HTTP/1.1 200 OK\r\n\r\n").unwrap();
            let _ = conn.shutdown(std::net::Shutdown::Write);
        });

        let dead_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let dead_port = dead_listener.local_addr().unwrap().port();
        drop(dead_listener);

        let (mut host_rx, mut host_tx, agent) = start_test_session();

        // Refused port returns ConnectError without killing session.
        send_message(
            &mut host_tx,
            StreamId(1),
            &Message::ConnectStart {
                target: StreamTargetWire::GuestLoopbackTcp { port: dead_port },
            },
        )
        .unwrap();
        let err_frame = read_frame(&mut host_rx).unwrap();
        assert_eq!(err_frame.header.stream_id, StreamId(1));
        assert!(matches!(
            err_frame.decode_message().unwrap(),
            Message::ConnectError { .. }
        ));

        // Open real loopback TCP tunnel on StreamId(2).
        send_message(
            &mut host_tx,
            StreamId(2),
            &Message::ConnectStart {
                target: StreamTargetWire::GuestLoopbackTcp { port },
            },
        )
        .unwrap();
        let ack_frame = read_frame(&mut host_rx).unwrap();
        assert_eq!(ack_frame.header.stream_id, StreamId(2));
        assert_eq!(ack_frame.decode_message().unwrap(), Message::ConnectAck);

        // Duplicate active stream_id must be rejected with ConnectError.
        send_message(
            &mut host_tx,
            StreamId(2),
            &Message::ConnectStart {
                target: StreamTargetWire::GuestLoopbackTcp { port },
            },
        )
        .unwrap();
        let dup_frame = read_frame(&mut host_rx).unwrap();
        assert_eq!(dup_frame.header.stream_id, StreamId(2));
        assert!(matches!(
            dup_frame.decode_message().unwrap(),
            Message::ConnectError { .. }
        ));

        send_message(
            &mut host_tx,
            StreamId(2),
            &Message::StreamData {
                channel: StreamChannel::Stdin,
                eof: false,
                data: b"hello-".to_vec(),
            },
        )
        .unwrap();
        send_message(
            &mut host_tx,
            StreamId(2),
            &Message::StreamData {
                channel: StreamChannel::Stdin,
                eof: true,
                data: b"tunnel".to_vec(),
            },
        )
        .unwrap();

        let mut received = Vec::new();
        loop {
            let f = read_frame(&mut host_rx).unwrap();
            assert_eq!(f.header.stream_id, StreamId(2));
            match f.decode_message().unwrap() {
                Message::StreamData {
                    channel: StreamChannel::Stdout,
                    eof,
                    data,
                } => {
                    received.extend_from_slice(&data);
                    if eof {
                        break;
                    }
                }
                Message::StreamCredit {
                    channel: StreamChannel::Stdin,
                    ..
                } => {}
                other => panic!("unexpected tunnel response: {other:?}"),
            }
        }
        assert_eq!(received, b"HTTP/1.1 200 OK\r\n\r\n");

        send_message(&mut host_tx, StreamId(0), &Message::Ping { seq: 77 }).unwrap();
        let pong = read_frame(&mut host_rx).unwrap();
        assert_eq!(pong.decode_message().unwrap(), Message::Pong { seq: 77 });

        server.join().unwrap();
        shutdown_test_session(host_rx, host_tx, agent);
    }

    #[test]
    fn serve_session_configures_egress_listener_relays_egress_open_and_injects_exec_proxy_env() {
        use sandbox_protocol::{is_guest_stream_id, GUEST_STREAM_ID_BIT};
        use std::net::{Shutdown, TcpListener, TcpStream};

        let probe = TcpListener::bind(("0.0.0.0", 0)).unwrap();
        let proxy_port = probe.local_addr().unwrap().port();
        drop(probe);

        let (mut host_rx, mut host_tx, agent) = start_test_session();

        send_message(
            &mut host_tx,
            StreamId(0),
            &Message::ConfigureNetwork {
                enable_egress_proxy: true,
                proxy_port,
            },
        )
        .unwrap();

        let ack = read_frame(&mut host_rx).unwrap();
        assert_eq!(ack.header.stream_id, StreamId(0));
        assert_eq!(
            ack.decode_message().unwrap(),
            Message::ConfigureNetworkAck { proxy_port }
        );

        // Guest process sees automatic proxy env injection pointing to 127.0.0.1:<proxy_port>.
        #[cfg(windows)]
        let print_env_cmd = shell_cmd("echo %HTTP_PROXY%^|%NO_PROXY%");
        #[cfg(unix)]
        let print_env_cmd = shell_cmd("printf '%s|%s' \"$HTTP_PROXY\" \"$NO_PROXY\"");

        send_message(&mut host_tx, StreamId(1), &guest_exec_start(print_env_cmd)).unwrap();
        let (stdout, _stderr, _, _, exit_msg) = collect_exec_response(&mut host_rx, StreamId(1));
        assert!(matches!(exit_msg, Message::ExecExit { code: Some(0), .. }));
        let env_out = String::from_utf8_lossy(&stdout);
        assert!(
            env_out.contains(&format!("http://127.0.0.1:{proxy_port}|localhost,127.0.0.1,::1,10.88.0.1")),
            "unexpected env output: {env_out:?}"
        );

        // Connect to the guest proxy port and verify EgressOpen -> ConnectAck -> duplex relay.
        let mut guest_client = TcpStream::connect(("127.0.0.1", proxy_port)).unwrap();
        let open_frame = read_frame(&mut host_rx).unwrap();
        let guest_sid = open_frame.header.stream_id;
        assert!(is_guest_stream_id(guest_sid));
        assert_eq!(guest_sid, StreamId(GUEST_STREAM_ID_BIT | 1));
        assert_eq!(open_frame.decode_message().unwrap(), Message::EgressOpen);

        send_message(&mut host_tx, guest_sid, &Message::ConnectAck).unwrap();

        guest_client.write_all(b"GET http://example.com/ HTTP/1.1\r\n\r\n").unwrap();
        guest_client.shutdown(Shutdown::Write).unwrap();

        let mut forwarded = Vec::new();
        loop {
            let f = read_frame(&mut host_rx).unwrap();
            assert_eq!(f.header.stream_id, guest_sid);
            match f.decode_message().unwrap() {
                Message::StreamData {
                    channel: StreamChannel::Stdout,
                    eof,
                    data,
                } => {
                    forwarded.extend_from_slice(&data);
                    if eof {
                        break;
                    }
                }
                other => panic!("unexpected egress frame: {other:?}"),
            }
        }
        assert_eq!(forwarded, b"GET http://example.com/ HTTP/1.1\r\n\r\n");

        send_message(
            &mut host_tx,
            guest_sid,
            &Message::StreamData {
                channel: StreamChannel::Stdin,
                eof: true,
                data: b"HTTP/1.1 200 OK\r\n\r\nok".to_vec(),
            },
        )
        .unwrap();
        let mut resp = Vec::new();
        guest_client.read_to_end(&mut resp).unwrap();
        assert_eq!(resp, b"HTTP/1.1 200 OK\r\n\r\nok");

        // Disable network proxy cleanly and confirm ConfigureNetworkAck { proxy_port: 0 }.
        send_message(
            &mut host_tx,
            StreamId(0),
            &Message::ConfigureNetwork {
                enable_egress_proxy: false,
                proxy_port: 0,
            },
        )
        .unwrap();
        let disabled_ack = loop {
            let frame = read_frame(&mut host_rx).unwrap();
            if frame.header.stream_id == guest_sid
                && matches!(
                    frame.decode_message().unwrap(),
                    Message::StreamCredit {
                        channel: StreamChannel::Stdin,
                        ..
                    }
                )
            {
                continue;
            }
            break frame;
        };
        assert_eq!(disabled_ack.header.stream_id, StreamId(0));
        assert_eq!(
            disabled_ack.decode_message().unwrap(),
            Message::ConfigureNetworkAck { proxy_port: 0 }
        );

        shutdown_test_session(host_rx, host_tx, agent);
    }

    #[test]
    fn stream_close_aborts_inflight_copy_in_and_copy_out_cleanly() {
        let tmp = TestTempDir::new("copy-stream-close");
        let dst = tmp.path().join("copy-in-dst");
        let big_file = tmp.path().join("large.bin");
        std::fs::write(
            &big_file,
            vec![0xABu8; (INITIAL_STREAM_CREDIT_BYTES as usize) * 2 + 65_536],
        )
        .unwrap();

        let (mut host_rx, mut host_tx, agent) = start_test_session();

        // 1. Start CopyIn without ever sending EOF, then abort via StreamClose.
        send_message(
            &mut host_tx,
            StreamId(21),
            &Message::CopyInStart {
                dst_guest: dst.to_string_lossy().into_owned(),
                max_bytes: 1_048_576,
            },
        )
        .unwrap();
        send_message(&mut host_tx, StreamId(21), &Message::StreamClose).unwrap();

        // 2. Start CopyOut larger than initial credit so worker blocks on StreamCredit, then abort via StreamClose.
        send_message(
            &mut host_tx,
            StreamId(22),
            &Message::CopyOutStart {
                src_guest: big_file.to_string_lossy().into_owned(),
                max_bytes: 4 * 1_048_576,
            },
        )
        .unwrap();

        // Read first data chunk so we know CopyOut is actively streaming/waiting on credit.
        let first_frame = read_frame(&mut host_rx).unwrap();
        assert_eq!(first_frame.header.stream_id, StreamId(22));
        assert!(matches!(
            first_frame.decode_message().unwrap(),
            Message::StreamData {
                channel: StreamChannel::Stdout,
                eof: false,
                ..
            }
        ));

        send_message(&mut host_tx, StreamId(22), &Message::StreamClose).unwrap();

        // Drain any frames already queued before StreamClose took effect using Ping barrier.
        send_message(&mut host_tx, StreamId(0), &Message::Ping { seq: 901 }).unwrap();
        loop {
            let f = read_frame(&mut host_rx).unwrap();
            if f.header.stream_id == StreamId(0)
                && f.decode_message().unwrap() == (Message::Pong { seq: 901 })
            {
                break;
            }
        }

        // Shutdown joins all worker threads; would hang if CopyIn or CopyOut remained stuck.
        shutdown_test_session(host_rx, host_tx, agent);
    }
}
