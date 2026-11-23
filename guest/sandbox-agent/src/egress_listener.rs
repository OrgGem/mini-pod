//! Guest-side TCP egress proxy listener (`0.0.0.0:<port>`), `EgressOpen` virtio tunnel
//! initiator, and automatic guest/container proxy environment helpers.

use std::collections::{BTreeMap, HashMap};
use std::io;
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU32, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use sandbox_protocol::{
    is_guest_stream_id, Message, ProtocolError, StreamChannel, StreamId, GUEST_STREAM_ID_BIT,
    HOST_STREAM_ID_MAX, INITIAL_STREAM_CREDIT_BYTES,
};

use crate::tunnel::{relay_tunnel_socket, ActiveTunnel, TunnelSocket};
use crate::OutboundQueue;

pub(crate) const DEFAULT_NO_PROXY: &str = "localhost,127.0.0.1,::1,10.88.0.1";
const EGRESS_OPEN_ACK_TIMEOUT: Duration = Duration::from_secs(10);
const ACCEPT_WAKE_TIMEOUT: Duration = Duration::from_millis(500);

/// Returns the HTTP proxy URL reachable from guest processes and `podman system service`.
pub(crate) fn guest_proxy_url(port: u16) -> String {
    format!("http://127.0.0.1:{port}")
}

/// Returns the HTTP proxy URL reachable from bridged Podman containers via the `podman0` gateway.
pub(crate) fn container_proxy_url(port: u16) -> String {
    format!("http://10.88.0.1:{port}")
}

/// Builds the standard uppercase and lowercase proxy environment pairs for `proxy_url`.
pub(crate) fn default_proxy_env_pairs(proxy_url: &str) -> [(&'static str, String); 8] {
    [
        ("HTTP_PROXY", proxy_url.to_owned()),
        ("HTTPS_PROXY", proxy_url.to_owned()),
        ("ALL_PROXY", proxy_url.to_owned()),
        ("http_proxy", proxy_url.to_owned()),
        ("https_proxy", proxy_url.to_owned()),
        ("all_proxy", proxy_url.to_owned()),
        ("NO_PROXY", DEFAULT_NO_PROXY.to_owned()),
        ("no_proxy", DEFAULT_NO_PROXY.to_owned()),
    ]
}

/// Returns a copy of `user_env` populated with default proxy variables for any missing keys.
pub(crate) fn inject_default_proxy_env(
    user_env: &BTreeMap<String, String>,
    proxy_url: &str,
) -> BTreeMap<String, String> {
    let mut merged = user_env.clone();
    for (key, value) in default_proxy_env_pairs(proxy_url) {
        merged.entry(key.to_owned()).or_insert(value);
    }
    merged
}

struct ActiveListener {
    bind_ip: Ipv4Addr,
    requested_port: u16,
    bound_port: u16,
    stop: Arc<AtomicBool>,
    accept_thread: Option<JoinHandle<Vec<JoinHandle<()>>>>,
}

/// Manages the guest TCP egress proxy listener and outbound `EgressOpen` stream initiation.
pub(crate) struct EgressProxyManager {
    outbound: Arc<OutboundQueue>,
    active_tunnels: Arc<Mutex<HashMap<StreamId, Arc<ActiveTunnel>>>>,
    next_stream_seq: Arc<AtomicU32>,
    active_port: Arc<AtomicU16>,
    listener: Mutex<Option<ActiveListener>>,
}

impl EgressProxyManager {
    pub(crate) fn new(
        outbound: Arc<OutboundQueue>,
        active_tunnels: Arc<Mutex<HashMap<StreamId, Arc<ActiveTunnel>>>>,
    ) -> Self {
        Self {
            outbound,
            active_tunnels,
            next_stream_seq: Arc::new(AtomicU32::new(1)),
            active_port: Arc::new(AtomicU16::new(0)),
            listener: Mutex::new(None),
        }
    }

    /// Returns the active bound proxy port if egress proxying is currently enabled.
    pub(crate) fn active_proxy_port(&self) -> Option<u16> {
        let port = self.active_port.load(Ordering::Acquire);
        (port > 0).then_some(port)
    }

    /// Enables or disables the guest egress proxy listener on `0.0.0.0:<proxy_port>`.
    pub(crate) fn configure(&self, enable: bool, proxy_port: u16) -> Result<u16, ProtocolError> {
        if enable && proxy_port == 0 {
            return Err(ProtocolError::InvalidPayload(
                "ConfigureNetwork proxy_port must be nonzero when egress proxy is enabled"
                    .to_owned(),
            ));
        }
        self.configure_on(Ipv4Addr::UNSPECIFIED, enable, proxy_port)
    }

    pub(crate) fn configure_on(
        &self,
        bind_ip: Ipv4Addr,
        enable: bool,
        proxy_port: u16,
    ) -> Result<u16, ProtocolError> {
        let mut guard = self.listener.lock().unwrap_or_else(|e| e.into_inner());
        if !enable {
            self.active_port.store(0, Ordering::Release);
            let prev = guard.take();
            drop(guard);
            if let Some(prev) = prev {
                self.teardown_listener(prev);
            }
            return Ok(0);
        }

        if let Some(existing) = guard.as_ref() {
            if proxy_port != 0
                && existing.bind_ip == bind_ip
                && existing.requested_port == proxy_port
                && !existing.stop.load(Ordering::Acquire)
            {
                return Ok(existing.bound_port);
            }
        }

        if let Some(prev) = guard.take() {
            self.active_port.store(0, Ordering::Release);
            drop(guard);
            self.teardown_listener(prev);
            guard = self.listener.lock().unwrap_or_else(|e| e.into_inner());
        }

        let std_listener = TcpListener::bind((bind_ip, proxy_port))?;
        let bound_port = std_listener.local_addr()?.port();
        if bound_port == 0 {
            return Err(ProtocolError::Io(io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                "bound egress proxy listener reported port 0",
            )));
        }

        let stop = Arc::new(AtomicBool::new(false));
        let loop_stop = Arc::clone(&stop);
        let loop_outbound = Arc::clone(&self.outbound);
        let loop_tunnels = Arc::clone(&self.active_tunnels);
        let loop_seq = Arc::clone(&self.next_stream_seq);

        let accept_thread = thread::Builder::new()
            .name(format!("minipod-egress-{bound_port}"))
            .spawn(move || {
                run_accept_loop(
                    std_listener,
                    loop_stop,
                    loop_outbound,
                    loop_tunnels,
                    loop_seq,
                )
            })
            .map_err(ProtocolError::Io)?;

        self.active_port.store(bound_port, Ordering::Release);
        *guard = Some(ActiveListener {
            bind_ip,
            requested_port: proxy_port,
            bound_port,
            stop,
            accept_thread: Some(accept_thread),
        });
        Ok(bound_port)
    }

    /// Stops accepting new proxy connections, aborts active guest-initiated tunnels, and joins
    /// all listener and relay threads cleanly.
    pub(crate) fn shutdown(&self) {
        self.active_port.store(0, Ordering::Release);
        let prev = self
            .listener
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take();
        if let Some(prev) = prev {
            self.teardown_listener(prev);
        } else {
            self.close_guest_egress_tunnels();
        }
    }

    fn teardown_listener(&self, mut active: ActiveListener) {
        active.stop.store(true, Ordering::Release);
        let poke_addr = SocketAddr::from(([127, 0, 0, 1], active.bound_port));
        let _ = TcpStream::connect_timeout(&poke_addr, ACCEPT_WAKE_TIMEOUT);
        let relay_handles = active
            .accept_thread
            .take()
            .and_then(|handle| handle.join().ok())
            .unwrap_or_default();

        self.close_guest_egress_tunnels();
        for handle in relay_handles {
            let _ = handle.join();
        }
    }

    fn close_guest_egress_tunnels(&self) {
        let handles: Vec<Arc<ActiveTunnel>> = {
            let mut map = self
                .active_tunnels
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            let guest_ids: Vec<StreamId> = map
                .keys()
                .copied()
                .filter(|sid| is_guest_stream_id(*sid))
                .collect();
            guest_ids
                .into_iter()
                .filter_map(|sid| map.remove(&sid))
                .collect()
        };
        for handle in handles {
            handle.close(&self.outbound);
        }
    }
}

impl Drop for EgressProxyManager {
    fn drop(&mut self) {
        self.shutdown();
    }
}

fn run_accept_loop(
    listener: TcpListener,
    stop: Arc<AtomicBool>,
    outbound: Arc<OutboundQueue>,
    active_tunnels: Arc<Mutex<HashMap<StreamId, Arc<ActiveTunnel>>>>,
    next_stream_seq: Arc<AtomicU32>,
) -> Vec<JoinHandle<()>> {
    let mut relay_threads = Vec::new();
    loop {
        reap_finished(&mut relay_threads);
        match listener.accept() {
            Ok((stream, _peer)) => {
                if stop.load(Ordering::Acquire) || outbound.is_closed() {
                    drop(stream);
                    break;
                }
                if let Some(handle) =
                    spawn_egress_connection(stream, &outbound, &active_tunnels, &next_stream_seq)
                {
                    relay_threads.push(handle);
                }
            }
            Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
            Err(err) => {
                if !stop.load(Ordering::Acquire) {
                    eprintln!("[sandbox-agent] egress proxy accept error: {err}");
                }
                break;
            }
        }
    }
    relay_threads
}

fn spawn_egress_connection(
    stream: TcpStream,
    outbound: &Arc<OutboundQueue>,
    active_tunnels: &Arc<Mutex<HashMap<StreamId, Arc<ActiveTunnel>>>>,
    next_stream_seq: &AtomicU32,
) -> Option<JoinHandle<()>> {
    let Some(guest_sid) = allocate_guest_stream_id(next_stream_seq) else {
        eprintln!("[sandbox-agent] guest egress stream IDs exhausted");
        return None;
    };

    let _ = stream.set_nodelay(true);
    let Ok(abort_sock) = stream.try_clone() else {
        return None;
    };
    let Ok(writer_sock) = stream.try_clone() else {
        return None;
    };

    let (handle, stdin_rx, connect_rx) = ActiveTunnel::new_outbound(guest_sid);
    if handle
        .set_abort_socket(TunnelSocket::Tcp(abort_sock))
        .is_err()
    {
        return None;
    }

    {
        let mut map = active_tunnels.lock().unwrap_or_else(|e| e.into_inner());
        if map.contains_key(&guest_sid) {
            return None;
        }
        map.insert(guest_sid, Arc::clone(&handle));
    }

    outbound.seed_default_credit(
        guest_sid,
        StreamChannel::Stdout,
        INITIAL_STREAM_CREDIT_BYTES,
    );
    if outbound.push_message(guest_sid, &Message::EgressOpen).is_err() {
        active_tunnels
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&guest_sid);
        handle.close(outbound);
        outbound.clear_stream(guest_sid);
        return None;
    }

    let relay_outbound = Arc::clone(outbound);
    let relay_tunnels = Arc::clone(active_tunnels);
    let relay_handle = Arc::clone(&handle);
    match thread::Builder::new()
        .name(format!("minipod-egress-{}", guest_sid.0))
        .spawn(move || {
            let ack = connect_rx.recv_timeout(EGRESS_OPEN_ACK_TIMEOUT);
            let res = match ack {
                Ok(Ok(())) if !relay_handle.is_closed() => relay_tunnel_socket(
                    guest_sid,
                    TunnelSocket::Tcp(stream),
                    TunnelSocket::Tcp(writer_sock),
                    &relay_handle,
                    stdin_rx,
                    &relay_outbound,
                ),
                Ok(Ok(())) | Ok(Err(_)) | Err(mpsc::RecvTimeoutError::Disconnected) => {
                    relay_handle.close(&relay_outbound);
                    Ok(())
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    relay_handle.close(&relay_outbound);
                    let _ = relay_outbound.push_message(guest_sid, &Message::StreamClose);
                    Ok(())
                }
            };

            relay_tunnels
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&guest_sid);
            relay_handle.close_stdin_only();
            relay_outbound.clear_stream(guest_sid);

            if let Err(err) = res {
                eprintln!("[sandbox-agent] egress stream {guest_sid} transport error: {err}");
            }
        }) {
        Ok(thread_handle) => Some(thread_handle),
        Err(err) => {
            eprintln!("[sandbox-agent] failed to spawn egress relay thread {guest_sid}: {err}");
            active_tunnels
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&guest_sid);
            handle.close(outbound);
            let _ = outbound.push_message(guest_sid, &Message::StreamClose);
            outbound.clear_stream(guest_sid);
            None
        }
    }
}

fn allocate_guest_stream_id(next_seq: &AtomicU32) -> Option<StreamId> {
    loop {
        let seq = next_seq.load(Ordering::Acquire);
        if seq == 0 || seq > HOST_STREAM_ID_MAX {
            return None;
        }
        if next_seq
            .compare_exchange(seq, seq + 1, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            return Some(StreamId(GUEST_STREAM_ID_BIT | seq));
        }
    }
}

fn reap_finished(handles: &mut Vec<JoinHandle<()>>) {
    let mut i = 0;
    while i < handles.len() {
        if handles[i].is_finished() {
            let handle = handles.swap_remove(i);
            let _ = handle.join();
        } else {
            i += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::Shutdown;
    use sandbox_protocol::StreamChannel;

    #[test]
    fn guest_stream_id_allocation_sets_high_bit_and_skips_zero() {
        let seq = AtomicU32::new(1);
        assert_eq!(
            allocate_guest_stream_id(&seq),
            Some(StreamId(GUEST_STREAM_ID_BIT | 1))
        );
        assert_eq!(
            allocate_guest_stream_id(&seq),
            Some(StreamId(GUEST_STREAM_ID_BIT | 2))
        );

        let maxed = AtomicU32::new(HOST_STREAM_ID_MAX);
        assert_eq!(
            allocate_guest_stream_id(&maxed),
            Some(StreamId(u32::MAX))
        );
        assert_eq!(allocate_guest_stream_id(&maxed), None);
    }

    #[test]
    fn egress_listener_relays_full_duplex_and_half_close_via_egress_open() {
        let outbound = Arc::new(OutboundQueue::new());
        let active_tunnels = Arc::new(Mutex::new(HashMap::new()));
        let manager = EgressProxyManager::new(Arc::clone(&outbound), Arc::clone(&active_tunnels));

        assert_eq!(manager.active_proxy_port(), None);
        assert!(matches!(
            manager.configure(true, 0),
            Err(ProtocolError::InvalidPayload(_))
        ));

        let port = manager
            .configure_on(Ipv4Addr::LOCALHOST, true, 0)
            .expect("loopback listener binds");
        assert!(port > 0);
        assert_eq!(manager.active_proxy_port(), Some(port));

        let mut client = TcpStream::connect(("127.0.0.1", port)).unwrap();
        let open_frame = outbound.pop_for_writer().expect("EgressOpen expected");
        let guest_sid = open_frame.header.stream_id;
        assert!(is_guest_stream_id(guest_sid));
        assert_eq!(guest_sid, StreamId(GUEST_STREAM_ID_BIT | 1));
        assert_eq!(open_frame.decode_message().unwrap(), Message::EgressOpen);

        // Simulate Host acknowledging EgressOpen with ConnectAck.
        {
            let handle = active_tunnels
                .lock()
                .unwrap()
                .get(&guest_sid)
                .cloned()
                .expect("tunnel registered before EgressOpen");
            handle.resolve_connect(Ok(()));
        }

        // Guest client writes request and half-closes its write side while keeping read open.
        client.write_all(b"CONNECT example.com:443 HTTP/1.1\r\n\r\n").unwrap();
        client.shutdown(Shutdown::Write).unwrap();

        let mut forwarded_req = Vec::new();
        loop {
            let f = outbound.pop_for_writer().unwrap();
            assert_eq!(f.header.stream_id, guest_sid);
            match f.decode_message().unwrap() {
                Message::StreamData {
                    channel: StreamChannel::Stdout,
                    eof,
                    data,
                } => {
                    forwarded_req.extend_from_slice(&data);
                    if eof {
                        break;
                    }
                }
                other => panic!("unexpected frame from guest egress listener: {other:?}"),
            }
        }
        assert_eq!(
            forwarded_req,
            b"CONNECT example.com:443 HTTP/1.1\r\n\r\n"
        );

        // Host sends > 64 KiB response back via Stdin and half-closes Stdin.
        {
            let handle = active_tunnels.lock().unwrap().get(&guest_sid).cloned().unwrap();
            handle.push_stdin(vec![b'R'; 70_000], false, &outbound);
            handle.push_stdin(b"-END".to_vec(), true, &outbound);
        }

        let mut resp = Vec::new();
        client.read_to_end(&mut resp).unwrap();
        assert_eq!(resp.len(), 70_004);
        assert!(resp[..70_000].iter().all(|&b| b == b'R'));
        assert_eq!(&resp[70_000..], b"-END");

        // Disabling network proxy clears active port cleanly.
        assert_eq!(
            manager
                .configure_on(Ipv4Addr::LOCALHOST, false, 0)
                .unwrap(),
            0
        );
        assert_eq!(manager.active_proxy_port(), None);
        assert!(!active_tunnels.lock().unwrap().contains_key(&guest_sid));
    }

    #[test]
    fn egress_listener_closes_client_cleanly_on_connect_error() {
        let outbound = Arc::new(OutboundQueue::new());
        let active_tunnels = Arc::new(Mutex::new(HashMap::new()));
        let manager = EgressProxyManager::new(Arc::clone(&outbound), Arc::clone(&active_tunnels));

        let port = manager
            .configure_on(Ipv4Addr::LOCALHOST, true, 0)
            .expect("loopback listener binds");

        let mut client = TcpStream::connect(("127.0.0.1", port)).unwrap();
        let open_frame = outbound.pop_for_writer().unwrap();
        let guest_sid = open_frame.header.stream_id;

        // Simulate Host rejecting EgressOpen with ConnectError.
        if let Some(handle) = active_tunnels.lock().unwrap().remove(&guest_sid) {
            handle.resolve_connect(Err("proxy disabled".to_owned()));
            handle.close(&outbound);
        }

        let mut buf = [0u8; 32];
        let read_res = client.read(&mut buf);
        assert!(
            matches!(read_res, Ok(0) | Err(_)),
            "expected immediate EOF/reset after ConnectError, got {read_res:?}"
        );

        manager.shutdown();
        let st = outbound.state.lock().unwrap();
        assert!(
            st.credits.is_empty(),
            "rejected EgressOpen must clear seeded stream credits: {:?}",
            st.credits
        );
        assert!(
            st.aborted_streams.is_empty(),
            "rejected EgressOpen must clear aborted_streams entry: {:?}",
            st.aborted_streams
        );
    }
}
