//! Bidirectional stream tunnel relay (`GuestLoopbackTcp` and `PodmanUnixSocket`).

use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream};
#[cfg(unix)]
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::Duration;

use sandbox_protocol::{
    stream_frame_credit_cost, Message, ProtocolError, StreamChannel, StreamId, StreamTargetWire,
};

use crate::podman::PodmanServiceManager;
use crate::OutboundQueue;

const TUNNEL_READ_CHUNK_BYTES: usize = 64 * 1024;
const TCP_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_TUNNEL_STDIN_BUFFER_BYTES: usize = 2 * 1024 * 1024;

pub(crate) enum TunnelInput {
    Data { data: Vec<u8>, eof: bool },
}

struct TunnelState {
    closed: bool,
    stdin_tx: Option<mpsc::Sender<TunnelInput>>,
    connect_tx: Option<mpsc::Sender<Result<(), String>>>,
    abort_socket: Option<TunnelSocket>,
}

/// Active tunnel handle (host- or guest-initiated) supporting concurrent input, abort, and shutdown.
pub(crate) struct ActiveTunnel {
    stream_id: StreamId,
    queued_stdin_bytes: AtomicUsize,
    state: Mutex<TunnelState>,
}

impl ActiveTunnel {
    pub(crate) fn new(stream_id: StreamId) -> (Arc<Self>, mpsc::Receiver<TunnelInput>) {
        let (stdin_tx, stdin_rx) = mpsc::channel();
        let handle = Arc::new(Self {
            stream_id,
            queued_stdin_bytes: AtomicUsize::new(0),
            state: Mutex::new(TunnelState {
                closed: false,
                stdin_tx: Some(stdin_tx),
                connect_tx: None,
                abort_socket: None,
            }),
        });
        (handle, stdin_rx)
    }

    pub(crate) fn new_outbound(
        stream_id: StreamId,
    ) -> (
        Arc<Self>,
        mpsc::Receiver<TunnelInput>,
        mpsc::Receiver<Result<(), String>>,
    ) {
        let (stdin_tx, stdin_rx) = mpsc::channel();
        let (connect_tx, connect_rx) = mpsc::channel();
        let handle = Arc::new(Self {
            stream_id,
            queued_stdin_bytes: AtomicUsize::new(0),
            state: Mutex::new(TunnelState {
                closed: false,
                stdin_tx: Some(stdin_tx),
                connect_tx: Some(connect_tx),
                abort_socket: None,
            }),
        });
        (handle, stdin_rx, connect_rx)
    }

    pub(crate) fn resolve_connect(&self, result: Result<(), String>) {
        let tx = {
            let mut guard = self.state.lock().unwrap_or_else(|e| e.into_inner());
            if guard.closed {
                return;
            }
            guard.connect_tx.take()
        };
        if let Some(tx) = tx {
            let _ = tx.send(result);
        }
    }

    pub(crate) fn push_stdin(&self, data: Vec<u8>, eof: bool, outbound: &OutboundQueue) {
        if data.is_empty() && !eof {
            return;
        }
        let cost = stream_frame_credit_cost(data.len());
        let prev = self.queued_stdin_bytes.fetch_add(cost, Ordering::AcqRel);
        if prev.saturating_add(cost) > MAX_TUNNEL_STDIN_BUFFER_BYTES {
            self.queued_stdin_bytes.fetch_sub(cost, Ordering::AcqRel);
            self.close(outbound);
            let _ = outbound.push_message(self.stream_id, &Message::StreamClose);
            return;
        }

        let tx = {
            let mut guard = self.state.lock().unwrap_or_else(|e| e.into_inner());
            if guard.closed {
                None
            } else if eof {
                guard.stdin_tx.take()
            } else {
                guard.stdin_tx.clone()
            }
        };
        let sent = match tx {
            Some(tx) => tx.send(TunnelInput::Data { data, eof }).is_ok(),
            None => false,
        };
        if !sent && cost > 0 {
            self.queued_stdin_bytes.fetch_sub(cost, Ordering::AcqRel);
        }
    }

    fn release_stdin_bytes(&self, len: usize) {
        let cost = stream_frame_credit_cost(len);
        if cost > 0 {
            self.queued_stdin_bytes.fetch_sub(cost, Ordering::AcqRel);
        }
    }

    pub(crate) fn is_closed(&self) -> bool {
        self.state.lock().unwrap_or_else(|e| e.into_inner()).closed
    }

    /// Aborts the tunnel immediately, closing its stdin/connect channels and shutting down the socket.
    pub(crate) fn close(&self, outbound: &OutboundQueue) {
        let sock = {
            let mut guard = self.state.lock().unwrap_or_else(|e| e.into_inner());
            guard.closed = true;
            guard.stdin_tx.take();
            guard.connect_tx.take();
            guard.abort_socket.take()
        };
        outbound.abort_stream(self.stream_id);
        if let Some(sock) = sock {
            let _ = sock.shutdown(Shutdown::Both);
        }
    }

    pub(crate) fn set_abort_socket(&self, sock: TunnelSocket) -> Result<(), TunnelSocket> {
        let mut guard = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if guard.closed {
            return Err(sock);
        }
        guard.abort_socket = Some(sock);
        Ok(())
    }

    pub(crate) fn close_stdin_only(&self) {
        let mut guard = self.state.lock().unwrap_or_else(|e| e.into_inner());
        guard.stdin_tx.take();
        guard.connect_tx.take();
    }
}

pub(crate) enum TunnelSocket {
    Tcp(TcpStream),
    #[cfg(unix)]
    Unix(UnixStream),
}

impl TunnelSocket {
    fn try_clone(&self) -> io::Result<Self> {
        match self {
            Self::Tcp(stream) => stream.try_clone().map(Self::Tcp),
            #[cfg(unix)]
            Self::Unix(stream) => stream.try_clone().map(Self::Unix),
        }
    }

    fn shutdown(&self, how: Shutdown) -> io::Result<()> {
        match self {
            Self::Tcp(stream) => stream.shutdown(how),
            #[cfg(unix)]
            Self::Unix(stream) => stream.shutdown(how),
        }
    }

    fn enable_windows_abort_poll(&self) {
        // WinSock2 `shutdown(SD_BOTH)` does not wake an already-blocked `recv()` on Windows;
        // polling with a short read timeout lets host `cargo test` observe `handle.is_closed()`.
        #[cfg(windows)]
        match self {
            Self::Tcp(stream) => {
                let _ = stream.set_read_timeout(Some(Duration::from_millis(50)));
            }
        }
    }
}

impl Read for TunnelSocket {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Tcp(stream) => stream.read(buf),
            #[cfg(unix)]
            Self::Unix(stream) => stream.read(buf),
        }
    }
}

impl Write for TunnelSocket {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Self::Tcp(stream) => stream.write(buf),
            #[cfg(unix)]
            Self::Unix(stream) => stream.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Tcp(stream) => stream.flush(),
            #[cfg(unix)]
            Self::Unix(stream) => stream.flush(),
        }
    }
}

/// Validates a `ConnectStart` request synchronously; returns `Err(reason)` if rejected upfront.
pub(crate) fn validate_connect_request(
    stream_id: StreamId,
    target: StreamTargetWire,
    stream_in_use: bool,
) -> Result<(), String> {
    if stream_id == StreamId(0) || stream_in_use {
        return Err(format!(
            "invalid or duplicate stream_id {stream_id} for ConnectStart"
        ));
    }
    if let StreamTargetWire::GuestLoopbackTcp { port: 0 } = target {
        return Err("guest loopback TCP port must be greater than zero".to_owned());
    }
    Ok(())
}

/// Connects the requested guest tunnel target, acknowledges with `ConnectAck` (or
/// `ConnectError`), and relays bidirectional traffic until EOF or `StreamClose`.
pub(crate) fn run_tunnel(
    stream_id: StreamId,
    target: StreamTargetWire,
    handle: Arc<ActiveTunnel>,
    stdin_rx: mpsc::Receiver<TunnelInput>,
    outbound: Arc<OutboundQueue>,
    active_tunnels: Arc<Mutex<HashMap<StreamId, Arc<ActiveTunnel>>>>,
    podman: Arc<PodmanServiceManager>,
) {
    let res = run_tunnel_inner(stream_id, target, &handle, stdin_rx, &outbound, &podman);

    active_tunnels
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(&stream_id);
    handle.close_stdin_only();
    outbound.clear_stream(stream_id);

    if let Err(err) = res {
        eprintln!("[sandbox-agent] tunnel stream {stream_id} transport error: {err}");
    }
}

fn run_tunnel_inner(
    stream_id: StreamId,
    target: StreamTargetWire,
    handle: &Arc<ActiveTunnel>,
    stdin_rx: mpsc::Receiver<TunnelInput>,
    outbound: &Arc<OutboundQueue>,
    podman: &PodmanServiceManager,
) -> Result<(), ProtocolError> {
    let sock = match connect_target(target, podman) {
        Ok(sock) => sock,
        Err(reason) => {
            if handle.is_closed() {
                outbound.clear_stream(stream_id);
                return Ok(());
            }
            outbound.clear_stream(stream_id);
            return outbound.push_message(stream_id, &Message::ConnectError { message: reason });
        }
    };

    let abort_sock = match sock.try_clone() {
        Ok(cloned) => cloned,
        Err(err) => {
            outbound.clear_stream(stream_id);
            return outbound.push_message(
                stream_id,
                &Message::ConnectError {
                    message: format!("failed to clone guest tunnel socket: {err}"),
                },
            );
        }
    };
    let writer_sock = match sock.try_clone() {
        Ok(cloned) => cloned,
        Err(err) => {
            outbound.clear_stream(stream_id);
            return outbound.push_message(
                stream_id,
                &Message::ConnectError {
                    message: format!("failed to clone guest tunnel writer: {err}"),
                },
            );
        }
    };

    if let Err(sock_rejected) = handle.set_abort_socket(abort_sock) {
        let _ = sock_rejected.shutdown(Shutdown::Both);
        outbound.clear_stream(stream_id);
        return Ok(());
    }

    outbound.push_message(stream_id, &Message::ConnectAck)?;

    relay_tunnel_socket(stream_id, sock, writer_sock, handle, stdin_rx, outbound)
}

/// Relays bidirectional traffic between `reader_sock`/`writer_sock` and the multiplexed
/// `virtio-serial` stream (`StreamChannel::Stdout` outbound, `StreamChannel::Stdin` inbound)
/// while preserving independent half-close in both directions.
pub(crate) fn relay_tunnel_socket(
    stream_id: StreamId,
    mut reader_sock: TunnelSocket,
    mut writer_sock: TunnelSocket,
    handle: &Arc<ActiveTunnel>,
    stdin_rx: mpsc::Receiver<TunnelInput>,
    outbound: &OutboundQueue,
) -> Result<(), ProtocolError> {
    reader_sock.enable_windows_abort_poll();
    thread::scope(|scope| {
        let writer_handle = Arc::clone(handle);
        let writer_thread = scope.spawn(move || {
            pump_tunnel_writer(stream_id, stdin_rx, &mut writer_sock, &writer_handle, outbound)
        });

        let read_res = pump_tunnel_reader(stream_id, &mut reader_sock, handle, outbound);
        let write_failed = writer_thread.join().unwrap_or(false);
        if read_res.is_ok() && write_failed && !handle.is_closed() {
            outbound.enqueue_control_after_data(stream_id, &Message::StreamClose)?;
        }
        read_res
    })
}

fn connect_target(
    target: StreamTargetWire,
    podman: &PodmanServiceManager,
) -> Result<TunnelSocket, String> {
    match target {
        StreamTargetWire::GuestLoopbackTcp { port } => {
            if port == 0 {
                return Err("guest loopback TCP port must be greater than zero".to_owned());
            }
            let addr = SocketAddr::from(([127, 0, 0, 1], port));
            let stream = TcpStream::connect_timeout(&addr, TCP_CONNECT_TIMEOUT).map_err(|err| {
                format!("failed to connect guest loopback 127.0.0.1:{port}: {err}")
            })?;
            // On Windows, `connect_timeout` completes non-blocking `connect()` via `select()`,
            // leaving `mswsock` user-mode state unsynced until queried; sync via `peer_addr()`
            // before `try_clone()` (`WSADuplicateSocketW`) so cloned writers don't fail
            // `shutdown(Shutdown::Write)` with `WSAENOTCONN`.
            #[cfg(windows)]
            let _ = stream.peer_addr();
            let _ = stream.set_nodelay(true);
            Ok(TunnelSocket::Tcp(stream))
        }
        StreamTargetWire::PodmanUnixSocket => {
            #[cfg(unix)]
            {
                let sock_path = podman.ensure_running()?;
                let stream = UnixStream::connect(sock_path).map_err(|err| {
                    format!(
                        "failed to connect podman unix socket '{}': {err}",
                        sock_path.display()
                    )
                })?;
                Ok(TunnelSocket::Unix(stream))
            }
            #[cfg(not(unix))]
            {
                let _ = podman;
                Err("Podman Unix socket tunnels require a Unix guest environment".to_owned())
            }
        }
    }
}

fn pump_tunnel_writer(
    stream_id: StreamId,
    stdin_rx: mpsc::Receiver<TunnelInput>,
    writer: &mut TunnelSocket,
    handle: &ActiveTunnel,
    outbound: &OutboundQueue,
) -> bool {
    while let Ok(TunnelInput::Data { data, eof }) = stdin_rx.recv() {
        let len = data.len();
        if handle.is_closed() {
            handle.release_stdin_bytes(len);
            break;
        }
        if len > 0 && writer.write_all(&data).is_err() {
            handle.release_stdin_bytes(len);
            handle.close_stdin_only();
            let _ = writer.shutdown(Shutdown::Write);
            return true;
        }
        handle.release_stdin_bytes(len);
        if len > 0 && !eof {
            let _ = outbound.send_stdin_credit(stream_id, len);
        }
        if eof {
            let _ = writer.shutdown(Shutdown::Write);
            break;
        }
    }
    false
}

fn pump_tunnel_reader(
    stream_id: StreamId,
    reader: &mut TunnelSocket,
    handle: &ActiveTunnel,
    outbound: &OutboundQueue,
) -> Result<(), ProtocolError> {
    let mut buf = vec![0u8; TUNNEL_READ_CHUNK_BYTES];
    loop {
        match reader.read(&mut buf) {
            Ok(0) => {
                if handle.is_closed() {
                    outbound.clear_stream(stream_id);
                    return Ok(());
                }
                outbound.send_stream_eof(stream_id, StreamChannel::Stdout)?;
                outbound.clear_stream(stream_id);
                return Ok(());
            }
            Ok(n) => {
                if handle.is_closed() {
                    outbound.clear_stream(stream_id);
                    return Ok(());
                }
                outbound.send_stream_data(stream_id, StreamChannel::Stdout, &buf[..n])?;
            }
            Err(err)
                if err.kind() == io::ErrorKind::Interrupted
                    || (cfg!(windows)
                        && matches!(
                            err.kind(),
                            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                        )) =>
            {
                if handle.is_closed() {
                    outbound.clear_stream(stream_id);
                    return Ok(());
                }
                continue;
            }
            Err(_) => {
                if handle.is_closed() {
                    outbound.clear_stream(stream_id);
                    return Ok(());
                }
                handle.close(outbound);
                return outbound.enqueue_control_after_data(stream_id, &Message::StreamClose);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    #[test]
    fn validate_connect_request_rejects_port_zero_stream_zero_and_duplicates() {
        assert!(validate_connect_request(
            StreamId(0),
            StreamTargetWire::GuestLoopbackTcp { port: 80 },
            false
        )
        .is_err());

        assert!(validate_connect_request(
            StreamId(1),
            StreamTargetWire::GuestLoopbackTcp { port: 80 },
            true
        )
        .is_err());

        assert!(validate_connect_request(
            StreamId(1),
            StreamTargetWire::GuestLoopbackTcp { port: 0 },
            false
        )
        .is_err());

        assert!(validate_connect_request(
            StreamId(2),
            StreamTargetWire::GuestLoopbackTcp { port: 8080 },
            false
        )
        .is_ok());

        assert!(validate_connect_request(
            StreamId(3),
            StreamTargetWire::PodmanUnixSocket,
            false
        )
        .is_ok());
    }

    #[test]
    fn tcp_loopback_tunnel_supports_full_duplex_and_independent_half_close() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();

        let server = thread::spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            let mut req = Vec::new();
            // Blocks until client calls `shutdown(Shutdown::Write)` on `Stdin { eof: true }`.
            conn.read_to_end(&mut req).unwrap();
            assert_eq!(req, b"PING /health\n");

            // Send > 64 KiB response to exercise chunked `Stdout` streaming.
            let mut resp = vec![b'A'; 70_000];
            resp.extend_from_slice(b"-TAIL");
            conn.write_all(&resp).unwrap();
            let _ = conn.shutdown(Shutdown::Write);
        });

        let outbound = Arc::new(OutboundQueue::new());
        let active_tunnels = Arc::new(Mutex::new(HashMap::new()));
        let podman = Arc::new(PodmanServiceManager::new());

        let stream_id = StreamId(11);
        let (handle, stdin_rx) = ActiveTunnel::new(stream_id);
        active_tunnels
            .lock()
            .unwrap()
            .insert(stream_id, Arc::clone(&handle));

        let tunnel_outbound = Arc::clone(&outbound);
        let tunnel_map = Arc::clone(&active_tunnels);
        let tunnel_handle = Arc::clone(&handle);
        let worker = thread::spawn(move || {
            run_tunnel(
                stream_id,
                StreamTargetWire::GuestLoopbackTcp { port },
                tunnel_handle,
                stdin_rx,
                tunnel_outbound,
                tunnel_map,
                podman,
            );
        });

        // Push request then half-close Stdin while server response hasn't finished yet.
        handle.push_stdin(b"PING ".to_vec(), false, &outbound);
        handle.push_stdin(b"/health\n".to_vec(), true, &outbound);

        worker.join().unwrap();
        server.join().unwrap();
        outbound.finish_and_drain();

        let mut ack_seen = false;
        let mut stdin_credit_bytes = 0u64;
        let mut received = Vec::new();
        let mut eof_seen = false;
        while let Some(frame) = outbound.pop_for_writer() {
            assert_eq!(frame.header.stream_id, stream_id);
            match frame.decode_message().unwrap() {
                Message::ConnectAck => ack_seen = true,
                Message::StreamCredit {
                    channel: StreamChannel::Stdin,
                    bytes,
                } => {
                    stdin_credit_bytes += u64::from(bytes);
                }
                Message::StreamData {
                    channel: StreamChannel::Stdout,
                    eof,
                    data,
                } => {
                    received.extend_from_slice(&data);
                    if eof {
                        eof_seen = true;
                    }
                }
                other => panic!("unexpected frame: {other:?}"),
            }
        }

        assert!(ack_seen);
        assert_eq!(
            stdin_credit_bytes,
            stream_frame_credit_cost(b"PING ".len()) as u64
        );
        assert!(eof_seen);
        assert_eq!(received.len(), 70_005);
        assert!(received[..70_000].iter().all(|&b| b == b'A'));
        assert_eq!(&received[70_000..], b"-TAIL");
        assert!(!active_tunnels.lock().unwrap().contains_key(&stream_id));
    }

    #[test]
    fn tcp_loopback_tunnel_stream_close_unblocks_active_reader() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let (accepted_tx, accepted_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();

        let server = thread::spawn(move || {
            let (conn, _) = listener.accept().unwrap();
            let _ = accepted_tx.send(());
            let _ = release_rx.recv();
            drop(conn);
        });

        let outbound = Arc::new(OutboundQueue::new());
        let active_tunnels = Arc::new(Mutex::new(HashMap::new()));
        let podman = Arc::new(PodmanServiceManager::new());

        let stream_id = StreamId(12);
        let (handle, stdin_rx) = ActiveTunnel::new(stream_id);
        active_tunnels
            .lock()
            .unwrap()
            .insert(stream_id, Arc::clone(&handle));

        let tunnel_outbound = Arc::clone(&outbound);
        let tunnel_map = Arc::clone(&active_tunnels);
        let tunnel_handle = Arc::clone(&handle);
        let worker = thread::spawn(move || {
            run_tunnel(
                stream_id,
                StreamTargetWire::GuestLoopbackTcp { port },
                tunnel_handle,
                stdin_rx,
                tunnel_outbound,
                tunnel_map,
                podman,
            );
        });

        accepted_rx.recv().unwrap();
        // Wait until `ConnectAck` has been queued so abort_socket is guaranteed installed.
        loop {
            if let Some(frame) = outbound.pop_for_writer() {
                assert_eq!(frame.decode_message().unwrap(), Message::ConnectAck);
                break;
            }
        }
        // Let pump_tunnel_reader enter blocking read() before aborting the socket.
        thread::sleep(Duration::from_millis(15));

        handle.close(&outbound);
        worker.join().unwrap();
        let _ = release_tx.send(());
        server.join().unwrap();
        assert!(!active_tunnels.lock().unwrap().contains_key(&stream_id));
    }

    #[test]
    fn tcp_loopback_tunnel_emits_connect_error_on_refused_port() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let unused_port = listener.local_addr().unwrap().port();
        drop(listener);

        let outbound = Arc::new(OutboundQueue::new());
        let active_tunnels = Arc::new(Mutex::new(HashMap::new()));
        let podman = Arc::new(PodmanServiceManager::new());

        let stream_id = StreamId(13);
        let (handle, stdin_rx) = ActiveTunnel::new(stream_id);
        active_tunnels
            .lock()
            .unwrap()
            .insert(stream_id, Arc::clone(&handle));

        run_tunnel(
            stream_id,
            StreamTargetWire::GuestLoopbackTcp { port: unused_port },
            handle,
            stdin_rx,
            Arc::clone(&outbound),
            Arc::clone(&active_tunnels),
            podman,
        );
        outbound.finish_and_drain();

        let frame = outbound.pop_for_writer().expect("expected ConnectError frame");
        assert_eq!(frame.header.stream_id, stream_id);
        match frame.decode_message().unwrap() {
            Message::ConnectError { message } => {
                assert!(message.contains(&unused_port.to_string()), "msg={message}");
            }
            other => panic!("expected ConnectError, got {other:?}"),
        }
        assert!(outbound.pop_for_writer().is_none());
        assert!(!active_tunnels.lock().unwrap().contains_key(&stream_id));
    }

    #[test]
    fn active_tunnel_aborts_and_emits_stream_close_when_stdin_buffer_exceeds_cap() {
        let outbound = OutboundQueue::new();
        let stream_id = StreamId(99);
        let (handle, _stdin_rx) = ActiveTunnel::new(stream_id);

        handle.push_stdin(vec![b'a'; 1024 * 1024], false, &outbound);
        assert!(!handle.is_closed());

        // Exceed MAX_TUNNEL_STDIN_BUFFER_BYTES (2 MiB) without consumer draining _stdin_rx.
        handle.push_stdin(vec![b'b'; (1024 * 1024) + 1], false, &outbound);
        assert!(handle.is_closed());

        outbound.finish_and_drain();
        let close_frame = outbound.pop_for_writer().expect("StreamClose expected");
        assert_eq!(close_frame.header.stream_id, stream_id);
        assert_eq!(close_frame.decode_message().unwrap(), Message::StreamClose);
    }

    #[cfg(unix)]
    #[test]
    fn unix_tunnel_emits_stream_close_after_early_peer_read_shutdown() {
        let (host_side, mut peer) = UnixStream::pair().unwrap();
        let reader_sock = TunnelSocket::Unix(host_side.try_clone().unwrap());
        let writer_sock = TunnelSocket::Unix(host_side);

        let outbound = Arc::new(OutboundQueue::new());
        let stream_id = StreamId(15);
        outbound.seed_default_credit(stream_id, StreamChannel::Stdout, 1_048_576);
        let (handle, stdin_rx) = ActiveTunnel::new(stream_id);

        let (closed_tx, closed_rx) = mpsc::channel();
        let server = thread::spawn(move || {
            peer.shutdown(Shutdown::Read).unwrap();
            let _ = closed_tx.send(());
            peer.write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
                .unwrap();
            peer.shutdown(Shutdown::Write).unwrap();
        });

        let drain_outbound = Arc::clone(&outbound);
        let drainer = thread::spawn(move || {
            let mut frames = Vec::new();
            while let Some(frame) = drain_outbound.pop_for_writer() {
                frames.push(frame);
            }
            frames
        });

        let worker_outbound = Arc::clone(&outbound);
        let worker_handle = Arc::clone(&handle);
        let worker = thread::spawn(move || {
            relay_tunnel_socket(
                stream_id,
                reader_sock,
                writer_sock,
                &worker_handle,
                stdin_rx,
                &worker_outbound,
            )
            .unwrap();
        });

        closed_rx.recv().unwrap();
        handle.push_stdin(vec![b'P'; 1024], false, &outbound);

        worker.join().unwrap();
        server.join().unwrap();
        outbound.finish_and_drain();
        let frames = drainer.join().unwrap();

        let mut resp = Vec::new();
        let mut eof_idx = None;
        let mut close_idx = None;
        for (idx, frame) in frames.iter().enumerate() {
            match frame.decode_message().unwrap() {
                Message::StreamData {
                    channel: StreamChannel::Stdout,
                    eof,
                    data,
                } => {
                    resp.extend_from_slice(&data);
                    if eof {
                        eof_idx = Some(idx);
                    }
                }
                Message::StreamClose => close_idx = Some(idx),
                _ => {}
            }
        }
        assert_eq!(
            resp,
            b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n"
        );
        let eof_idx = eof_idx.expect("Stdout EOF expected");
        let close_idx = close_idx.expect("StreamClose after early peer Shutdown::Read expected");
        assert!(
            close_idx > eof_idx,
            "StreamClose ({close_idx}) must arrive after Stdout EOF ({eof_idx})"
        );
    }

    #[test]
    fn active_tunnel_ignores_empty_non_eof_and_accounts_small_frame_overhead() {
        let outbound = OutboundQueue::new();
        let stream_id = StreamId(100);
        let (handle, stdin_rx) = ActiveTunnel::new(stream_id);

        handle.push_stdin(Vec::new(), false, &outbound);
        assert!(stdin_rx.try_recv().is_err(), "empty non-EOF frame must be ignored");
        assert_eq!(handle.queued_stdin_bytes.load(Ordering::Acquire), 0);

        // 32,768 chunks of 1 byte cost 65 bytes each (= 2,129,920 > 2 MiB) so cap must trip.
        for _ in 0..32_768 {
            handle.push_stdin(vec![b'x'], false, &outbound);
            if handle.is_closed() {
                break;
            }
        }
        assert!(
            handle.is_closed(),
            "tiny-chunk Stdin flood must trip 2 MiB cap via per-frame overhead"
        );
    }
}
