//! Host loopback TCP port forward registry and bidirectional virtio tunnel listeners.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{Context, Poll};
use std::time::Duration;

use sandbox_core::{SandboxError, SandboxId};
use sandbox_runtime::SandboxTunnelPort;
use serde_json::Value;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpListener;
use tokio::task::{AbortHandle, JoinHandle, JoinSet};

use crate::policy::{parse_port_key, RequestedPortBinding};

const HOST_LOOPBACK_IP: &str = "127.0.0.1";
const MIN_SHORT_ID_PREFIX_LEN: usize = 12;
pub const MAX_CONCURRENT_PORT_FORWARD_CONNS: usize = 64;
const PORT_FORWARD_OPEN_TIMEOUT: Duration = Duration::from_secs(10);
const PORT_FORWARD_IDLE_TIMEOUT: Duration = Duration::from_secs(120);

/// Public snapshot of an active Host loopback -> Guest loopback port forward.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActivePortForward {
    pub container_key: String,
    pub container_port: u16,
    pub protocol: String,
    pub host_ip: String,
    pub host_port: u16,
    pub guest_port: u16,
}

struct PortBinding {
    container_key: String,
    container_port: u16,
    protocol: String,
    host_ip: String,
    host_port: u16,
    guest_port: u16,
    task_abort: AbortHandle,
    task_join: Option<JoinHandle<()>>,
}

impl PortBinding {
    fn to_active(&self) -> ActivePortForward {
        ActivePortForward {
            container_key: self.container_key.clone(),
            container_port: self.container_port,
            protocol: self.protocol.clone(),
            host_ip: self.host_ip.clone(),
            host_port: self.host_port,
            guest_port: self.guest_port,
        }
    }
}

impl Drop for PortBinding {
    fn drop(&mut self) {
        self.task_abort.abort();
    }
}

#[derive(Default)]
struct RegistryState {
    known_ids: HashSet<String>,
    aliases: HashMap<String, String>,
    pending_ports: HashMap<String, Vec<RequestedPortBinding>>,
    active_forwards: HashMap<String, Vec<PortBinding>>,
}

/// Tracks container ID/name aliases, pending requested port bindings, and live Host TCP listeners.
#[derive(Default)]
pub struct PortForwardRegistry {
    state: Mutex<RegistryState>,
}

impl fmt::Debug for PortForwardRegistry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let guard = lock_unpoisoned(&self.state);
        f.debug_struct("PortForwardRegistry")
            .field("known_containers", &guard.known_ids.len())
            .field("active_containers", &guard.active_forwards.len())
            .finish()
    }
}

impl Drop for PortForwardRegistry {
    fn drop(&mut self) {
        self.release_all();
    }
}

impl PortForwardRegistry {
    /// Creates an empty port forward registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Records requested port bindings and optional container name alias from `POST /containers/create`.
    pub fn record_create(
        &self,
        container_id: &str,
        name: Option<&str>,
        ports: Vec<RequestedPortBinding>,
    ) {
        let canonical_id = container_id.trim();
        if canonical_id.is_empty() {
            return;
        }

        let mut guard = lock_unpoisoned(&self.state);
        guard.known_ids.insert(canonical_id.to_owned());
        if let Some(raw_name) = name {
            let normalized = normalize_container_name(raw_name);
            if !normalized.is_empty() && normalized != canonical_id {
                guard
                    .aliases
                    .insert(normalized.to_owned(), canonical_id.to_owned());
            }
        }
        guard.pending_ports.insert(canonical_id.to_owned(), ports);
    }

    /// Maps a container name or >=12-char short ID prefix to its canonical container ID when known.
    pub fn resolve_id(&self, id_or_name: &str) -> String {
        let guard = lock_unpoisoned(&self.state);
        resolve_id_locked(&guard, id_or_name)
    }

    /// Extracts Podman's bound guest loopback ports from `inspect_json`, tears down any stale
    /// forwards for `container_id`, binds Host `127.0.0.1` TCP listeners upfront, and spawns
    /// bidirectional accept loops over `tunnel_port`.
    pub async fn activate_container_forwards(
        &self,
        tunnel_port: Arc<dyn SandboxTunnelPort>,
        sandbox_id: &SandboxId,
        container_id: &str,
        inspect_json: &Value,
    ) -> Result<Vec<ActivePortForward>, SandboxError> {
        let inspect_id = inspect_json
            .get("Id")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty());
        let inspect_name = inspect_json
            .get("Name")
            .and_then(Value::as_str)
            .map(normalize_container_name)
            .filter(|s| !s.is_empty());

        let (canonical_id, pending, stale_bindings) = {
            let mut guard = lock_unpoisoned(&self.state);
            let resolved_input = resolve_id_locked(&guard, container_id);
            let canonical_id = inspect_id
                .map(str::to_owned)
                .unwrap_or_else(|| resolved_input.clone());

            guard.known_ids.insert(canonical_id.clone());
            if let Some(name) = inspect_name {
                if name != canonical_id {
                    guard.aliases.insert(name.to_owned(), canonical_id.clone());
                }
            }
            let norm_input = normalize_container_name(container_id);
            if !norm_input.is_empty()
                && norm_input != canonical_id
                && !canonical_id.starts_with(norm_input)
            {
                guard
                    .aliases
                    .insert(norm_input.to_owned(), canonical_id.clone());
            }

            let pending = guard
                .pending_ports
                .get(&canonical_id)
                .or_else(|| guard.pending_ports.get(&resolved_input))
                .cloned();

            let mut stale = guard
                .active_forwards
                .remove(&canonical_id)
                .unwrap_or_default();
            if resolved_input != canonical_id {
                if let Some(extra) = guard.active_forwards.remove(&resolved_input) {
                    stale.extend(extra);
                }
            }
            (canonical_id, pending, stale)
        };

        // Ensure stale listeners (e.g. during container restart) close their OS sockets before re-bind.
        abort_and_join_bindings(stale_bindings).await;

        let planned = resolve_planned_bindings(pending.as_deref(), inspect_json)?;
        if planned.is_empty() {
            return Ok(Vec::new());
        }

        let mut new_bindings = Vec::with_capacity(planned.len());
        let mut active_summary = Vec::with_capacity(planned.len());

        for item in planned {
            let bind_addr =
                SocketAddr::from(([127, 0, 0, 1], item.requested_host_port.unwrap_or(0)));
            let listener = match TcpListener::bind(bind_addr).await {
                Ok(listener) => listener,
                Err(err) => {
                    abort_and_join_bindings(new_bindings).await;
                    return Err(SandboxError::Transport(format!(
                        "failed to bind host forward {bind_addr} for container '{canonical_id}' ({}): {err}",
                        item.container_key
                    )));
                }
            };
            let actual_host_port = match listener.local_addr() {
                Ok(addr) => addr.port(),
                Err(err) => {
                    drop(listener);
                    abort_and_join_bindings(new_bindings).await;
                    return Err(SandboxError::Transport(format!(
                        "failed to query bound host port for container '{canonical_id}' ({}): {err}",
                        item.container_key
                    )));
                }
            };

            let tunnel = Arc::clone(&tunnel_port);
            let sbx_id = sandbox_id.clone();
            let guest_port = item.guest_port;
            let join = tokio::spawn(async move {
                accept_loop(listener, tunnel, sbx_id, guest_port).await;
            });
            let task_abort = join.abort_handle();

            let binding = PortBinding {
                container_key: item.container_key,
                container_port: item.container_port,
                protocol: item.protocol,
                host_ip: HOST_LOOPBACK_IP.to_owned(),
                host_port: actual_host_port,
                guest_port: item.guest_port,
                task_abort,
                task_join: Some(join),
            };
            active_summary.push(binding.to_active());
            new_bindings.push(binding);
        }

        let displaced = {
            let mut guard = lock_unpoisoned(&self.state);
            guard.active_forwards.insert(canonical_id, new_bindings)
        };
        if let Some(old) = displaced {
            abort_and_join_bindings(old).await;
        }

        Ok(active_summary)
    }

    /// Aborts all active port forward listeners for `id_or_name` and drops their bindings.
    pub fn release_container_forwards(&self, id_or_name: &str) {
        let bindings = {
            let mut guard = lock_unpoisoned(&self.state);
            let canonical_id = resolve_id_locked(&guard, id_or_name);
            guard
                .active_forwards
                .remove(&canonical_id)
                .unwrap_or_default()
        };
        for binding in bindings {
            binding.task_abort.abort();
        }
    }

    /// Aborts active port forward listeners and awaits their socket closure; optionally removes
    /// pending port metadata and aliases (on `DELETE`).
    pub(crate) async fn release_container_forwards_async(&self, id_or_name: &str, forget: bool) {
        let bindings = {
            let mut guard = lock_unpoisoned(&self.state);
            let canonical_id = resolve_id_locked(&guard, id_or_name);
            let removed = guard
                .active_forwards
                .remove(&canonical_id)
                .unwrap_or_default();
            if forget {
                guard.known_ids.remove(&canonical_id);
                guard.pending_ports.remove(&canonical_id);
                guard.aliases.retain(|_, v| v != &canonical_id);
            }
            removed
        };
        abort_and_join_bindings(bindings).await;
    }

    /// Aborts every active listener task across all containers and clears all state.
    pub fn release_all(&self) {
        let all_bindings: Vec<PortBinding> = {
            let mut guard = lock_unpoisoned(&self.state);
            guard.known_ids.clear();
            guard.aliases.clear();
            guard.pending_ports.clear();
            guard
                .active_forwards
                .drain()
                .flat_map(|(_, list)| list)
                .collect()
        };
        for binding in all_bindings {
            binding.task_abort.abort();
        }
    }

    /// Returns a snapshot of active host port forwards for `id_or_name`.
    pub fn snapshot_for_container(&self, id_or_name: &str) -> Vec<ActivePortForward> {
        let guard = lock_unpoisoned(&self.state);
        let canonical_id = resolve_id_locked(&guard, id_or_name);
        guard
            .active_forwards
            .get(&canonical_id)
            .map(|list| list.iter().map(PortBinding::to_active).collect())
            .unwrap_or_default()
    }
}

struct PlannedPortForward {
    container_key: String,
    container_port: u16,
    protocol: String,
    requested_host_port: Option<u16>,
    guest_port: u16,
}

fn resolve_planned_bindings(
    pending: Option<&[RequestedPortBinding]>,
    inspect_json: &Value,
) -> Result<Vec<PlannedPortForward>, SandboxError> {
    let ports_obj = inspect_json
        .get("NetworkSettings")
        .and_then(|ns| ns.get("Ports"))
        .and_then(Value::as_object);

    if let Some(requested) = pending.filter(|list| !list.is_empty()) {
        let ports_map = ports_obj.ok_or_else(|| {
            SandboxError::Transport(
                "container inspect JSON missing NetworkSettings.Ports for requested ports"
                    .to_owned(),
            )
        })?;

        let mut seen_indices: HashMap<&str, usize> = HashMap::new();
        let mut out = Vec::with_capacity(requested.len());
        for req in requested {
            let idx = seen_indices.entry(req.container_key.as_str()).or_insert(0);
            let entries = ports_map
                .get(&req.container_key)
                .and_then(Value::as_array)
                .ok_or_else(|| {
                    SandboxError::Transport(format!(
                        "container inspect JSON missing bound guest port array for '{}'",
                        req.container_key
                    ))
                })?;
            let entry = entries.get(*idx).or_else(|| entries.first()).ok_or_else(|| {
                SandboxError::Transport(format!(
                    "container inspect JSON has empty binding list for '{}'",
                    req.container_key
                ))
            })?;
            *idx += 1;

            let guest_port = parse_bound_guest_port(entry, &req.container_key)?;
            out.push(PlannedPortForward {
                container_key: req.container_key.clone(),
                container_port: req.container_port,
                protocol: req.protocol.clone(),
                requested_host_port: req.host_port,
                guest_port,
            });
        }
        return Ok(out);
    }

    // Fallback discovery when container was created outside this proxy session.
    let Some(ports_map) = ports_obj else {
        return Ok(Vec::new());
    };
    let mut discovered = Vec::new();
    for (raw_key, val) in ports_map {
        let Some(entries) = val.as_array() else {
            continue;
        };
        let Ok((container_port, protocol)) = parse_port_key(raw_key) else {
            continue;
        };
        if protocol != "tcp" {
            continue;
        }
        let canonical_key = format!("{container_port}/tcp");
        for entry in entries {
            if let Ok(guest_port) = parse_bound_guest_port(entry, &canonical_key) {
                discovered.push(PlannedPortForward {
                    container_key: canonical_key.clone(),
                    container_port,
                    protocol: "tcp".to_owned(),
                    requested_host_port: None,
                    guest_port,
                });
            }
        }
    }
    Ok(discovered)
}

fn parse_bound_guest_port(entry: &Value, container_key: &str) -> Result<u16, SandboxError> {
    let obj = entry.as_object().ok_or_else(|| {
        SandboxError::Transport(format!(
            "NetworkSettings.Ports['{container_key}'] entry must be a JSON object"
        ))
    })?;

    if let Some(ip_val) = obj.get("HostIp").and_then(Value::as_str) {
        let ip = ip_val.trim();
        if !matches!(ip, "" | "127.0.0.1" | "0.0.0.0" | "::1") {
            return Err(SandboxError::PolicyViolation(format!(
                "refusing non-loopback guest port binding HostIp '{ip}' on '{container_key}'"
            )));
        }
    }

    let raw_port = obj
        .get("HostPort")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            SandboxError::Transport(format!(
                "NetworkSettings.Ports['{container_key}'] binding missing HostPort"
            ))
        })?;

    let port: u16 = raw_port.parse().map_err(|_| {
        SandboxError::Transport(format!(
            "invalid guest HostPort '{raw_port}' on '{container_key}'"
        ))
    })?;
    if port == 0 {
        return Err(SandboxError::Transport(format!(
            "invalid guest HostPort '0' on '{container_key}'"
        )));
    }
    Ok(port)
}

struct IdleTrackedIo<'a, S: Unpin> {
    inner: &'a mut S,
    activity: &'a AtomicU64,
}

impl<S: AsyncRead + Unpin> AsyncRead for IdleTrackedIo<'_, S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let poll = Pin::new(&mut *self.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &poll {
            if buf.filled().len() > before {
                self.activity.fetch_add(1, AtomicOrdering::Relaxed);
            }
        }
        poll
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for IdleTrackedIo<'_, S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let poll = Pin::new(&mut *self.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = &poll {
            if *n > 0 {
                self.activity.fetch_add(1, AtomicOrdering::Relaxed);
            }
        }
        poll
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let poll = Pin::new(&mut *self.inner).poll_shutdown(cx);
        if let Poll::Ready(Ok(())) = &poll {
            self.activity.fetch_add(1, AtomicOrdering::Relaxed);
        }
        poll
    }
}

async fn wait_for_idle(activity: &AtomicU64, idle_timeout: Duration) {
    let mut last = activity.load(AtomicOrdering::Relaxed);
    loop {
        tokio::time::sleep(idle_timeout).await;
        let current = activity.load(AtomicOrdering::Relaxed);
        if current == last {
            return;
        }
        last = current;
    }
}

async fn accept_loop(
    listener: TcpListener,
    tunnel_port: Arc<dyn SandboxTunnelPort>,
    sandbox_id: SandboxId,
    guest_port: u16,
) {
    let mut connections: JoinSet<()> = JoinSet::new();
    loop {
        let accepted = tokio::select! {
            biased;
            Some(_) = connections.join_next(), if !connections.is_empty() => continue,
            res = listener.accept() => res,
        };
        let (mut client_stream, _) = match accepted {
            Ok(conn) => conn,
            Err(err) => {
                if matches!(
                    err.kind(),
                    std::io::ErrorKind::ConnectionAborted
                        | std::io::ErrorKind::ConnectionReset
                        | std::io::ErrorKind::Interrupted
                ) {
                    continue;
                }
                break;
            }
        };

        while connections.try_join_next().is_some() {}
        if connections.len() >= MAX_CONCURRENT_PORT_FORWARD_CONNS {
            let _ = client_stream.shutdown().await;
            drop(client_stream);
            continue;
        }

        let _ = client_stream.set_nodelay(true);
        let tunnel = Arc::clone(&tunnel_port);
        let sbx = sandbox_id.clone();
        connections.spawn(async move {
            let Ok(Ok(mut guest_stream)) = tokio::time::timeout(
                PORT_FORWARD_OPEN_TIMEOUT,
                tunnel.open_guest_tcp_stream(&sbx, guest_port),
            )
            .await
            else {
                let _ = client_stream.shutdown().await;
                return;
            };

            let activity = AtomicU64::new(0);
            let mut tracked_client = IdleTrackedIo {
                inner: &mut client_stream,
                activity: &activity,
            };
            let mut tracked_guest = IdleTrackedIo {
                inner: &mut guest_stream,
                activity: &activity,
            };
            tokio::select! {
                biased;
                _ = wait_for_idle(&activity, PORT_FORWARD_IDLE_TIMEOUT) => {}
                _ = tokio::io::copy_bidirectional(&mut tracked_client, &mut tracked_guest) => {}
            }
        });
    }
}

async fn abort_and_join_bindings(bindings: Vec<PortBinding>) {
    for mut binding in bindings {
        binding.task_abort.abort();
        if let Some(join) = binding.task_join.take() {
            let _ = join.await;
        }
    }
}

fn resolve_id_locked(state: &RegistryState, id_or_name: &str) -> String {
    let key = normalize_container_name(id_or_name);
    if key.is_empty() {
        return id_or_name.to_owned();
    }
    if state.known_ids.contains(key)
        || state.pending_ports.contains_key(key)
        || state.active_forwards.contains_key(key)
    {
        return key.to_owned();
    }
    if let Some(canonical) = state.aliases.get(key) {
        return canonical.clone();
    }
    if key.len() >= MIN_SHORT_ID_PREFIX_LEN {
        let mut matched: Option<&String> = None;
        let mut ambiguous = false;
        for candidate in &state.known_ids {
            if candidate.starts_with(key) {
                if matched.is_some() {
                    ambiguous = true;
                    break;
                }
                matched = Some(candidate);
            }
        }
        if !ambiguous {
            if let Some(found) = matched {
                return found.clone();
            }
        }
    }
    id_or_name.to_owned()
}

fn normalize_container_name(raw: &str) -> &str {
    raw.trim().trim_start_matches('/')
}

fn lock_unpoisoned<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::time::Duration;

    use sandbox_core::{DestroyStatus, ExecRequest, SandboxLease, SandboxSpec};
    use sandbox_protocol::StreamId;
    use sandbox_runtime::{ExecStream, RuntimeManager, TunnelStream, TunnelStreamHandle};
    use serde_json::json;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    struct MockTcpTunnelPort {
        expected_guest_port: u16,
        half_close_mode: bool,
    }

    #[async_trait::async_trait]
    impl RuntimeManager for MockTcpTunnelPort {
        async fn spawn(&self, _spec: SandboxSpec) -> Result<SandboxLease, SandboxError> {
            unreachable!()
        }
        async fn renew_lease(&self, _id: &SandboxId, _ttl: Duration) -> Result<(), SandboxError> {
            unreachable!()
        }
        async fn exec_stream(
            &self,
            _id: &SandboxId,
            _req: ExecRequest,
        ) -> Result<ExecStream, SandboxError> {
            unreachable!()
        }
        async fn copy_in(
            &self,
            _id: &SandboxId,
            _src_host: PathBuf,
            _dst_guest: String,
        ) -> Result<(), SandboxError> {
            unreachable!()
        }
        async fn copy_out(
            &self,
            _id: &SandboxId,
            _src_guest: String,
            _dst_host: PathBuf,
        ) -> Result<(), SandboxError> {
            unreachable!()
        }
        async fn destroy(&self, _id: &SandboxId) -> Result<DestroyStatus, SandboxError> {
            unreachable!()
        }
    }

    #[async_trait::async_trait]
    impl SandboxTunnelPort for MockTcpTunnelPort {
        async fn open_podman_unix_stream(
            &self,
            _id: &SandboxId,
        ) -> Result<TunnelStream, SandboxError> {
            Err(SandboxError::Transport("unused in ports test".to_owned()))
        }

        async fn open_guest_tcp_stream(
            &self,
            _id: &SandboxId,
            guest_port: u16,
        ) -> Result<TunnelStream, SandboxError> {
            assert_eq!(guest_port, self.expected_guest_port);
            let (stream, handle): (TunnelStream, TunnelStreamHandle) =
                TunnelStream::channel(StreamId(1));
            let half_close_mode = self.half_close_mode;
            tokio::spawn(async move {
                let mut reader = handle.read_half;
                let mut writer = handle.write_half;
                let _drop_rx = handle.drop_rx;

                if half_close_mode {
                    let mut all_in = Vec::new();
                    reader.read_to_end(&mut all_in).await.unwrap();
                    let mut reply = b"ack:".to_vec();
                    reply.extend_from_slice(&all_in);
                    writer.write_all(&reply).await.unwrap();
                    writer.shutdown().await.unwrap();
                } else {
                    let mut buf = [0u8; 1024];
                    loop {
                        let n = reader.read(&mut buf).await.unwrap_or(0);
                        if n == 0 {
                            let _ = writer.shutdown().await;
                            break;
                        }
                        if writer.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                        let _ = writer.flush().await;
                    }
                }
            });
            Ok(stream)
        }
    }

    #[tokio::test]
    async fn resolve_id_handles_name_short_prefix_and_unknown_fallback() {
        let reg = PortForwardRegistry::new();
        let full_id = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        reg.record_create(full_id, Some("/pg-test"), Vec::new());

        assert_eq!(reg.resolve_id("pg-test"), full_id);
        assert_eq!(reg.resolve_id("/pg-test"), full_id);
        assert_eq!(reg.resolve_id("0123456789ab"), full_id);
        assert_eq!(reg.resolve_id(full_id), full_id);
        assert_eq!(reg.resolve_id("0123456789a"), "0123456789a");
        assert_eq!(reg.resolve_id("unknown-box"), "unknown-box");
    }

    #[tokio::test]
    async fn forwards_tcp_traffic_with_half_close_and_releases_ports_on_release_and_drop() {
        let full_id = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        let reg = PortForwardRegistry::new();
        reg.record_create(
            full_id,
            Some("echo-svc"),
            vec![RequestedPortBinding {
                container_port: 8080,
                protocol: "tcp".to_owned(),
                host_port: None,
                container_key: "8080/tcp".to_owned(),
            }],
        );

        let inspect = json!({
            "Id": full_id,
            "Name": "/echo-svc",
            "NetworkSettings": {
                "Ports": {
                    "8080/tcp": [{ "HostIp": "127.0.0.1", "HostPort": "43210" }]
                }
            }
        });

        let tunnel: Arc<dyn SandboxTunnelPort> = Arc::new(MockTcpTunnelPort {
            expected_guest_port: 43210,
            half_close_mode: true,
        });
        let sbx_id = SandboxId::new("sbx-port-test");
        let forwards = reg
            .activate_container_forwards(Arc::clone(&tunnel), &sbx_id, "echo-svc", &inspect)
            .await
            .expect("activate forwards");
        assert_eq!(forwards.len(), 1);
        let bound_port = forwards[0].host_port;
        assert_ne!(bound_port, 0);
        assert_eq!(forwards[0].guest_port, 43210);
        assert_eq!(reg.snapshot_for_container("abcdef012345"), forwards);

        // Connect over loopback TCP, send payload, half-close write side, and receive full response.
        let mut client = TcpStream::connect(("127.0.0.1", bound_port))
            .await
            .expect("connect to forwarded host port");
        client.write_all(b"hello-virtio").await.unwrap();
        client.shutdown().await.unwrap();

        let mut received = Vec::new();
        client.read_to_end(&mut received).await.unwrap();
        assert_eq!(received, b"ack:hello-virtio");

        // Releasing container forwards frees the host TCP port deterministically.
        reg.release_container_forwards_async("echo-svc", false).await;
        assert!(reg.snapshot_for_container(full_id).is_empty());
        assert!(TcpStream::connect(("127.0.0.1", bound_port))
            .await
            .is_err());

        // Re-activating (like start after stop) binds again cleanly, and Drop releases all ports.
        let forwards2 = reg
            .activate_container_forwards(tunnel, &sbx_id, full_id, &inspect)
            .await
            .expect("re-activate after stop");
        let bound_port2 = forwards2[0].host_port;
        drop(reg);
        tokio::task::yield_now().await;
        assert!(TcpStream::connect(("127.0.0.1", bound_port2))
            .await
            .is_err());
    }

    #[tokio::test]
    async fn discovers_ports_from_inspect_json_without_prior_record_create_and_restarts_fixed_port() {
        let probe = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let fixed_host_port = probe.local_addr().unwrap().port();
        drop(probe);

        let reg = PortForwardRegistry::new();
        let sbx_id = SandboxId::new("sbx-restart");

        // Case 1: External container without record_create discovers published loopback binding.
        let ext_inspect = json!({
            "Id": "1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff",
            "NetworkSettings": {
                "Ports": {
                    "80/tcp": [{ "HostIp": "127.0.0.1", "HostPort": "49001" }],
                    "443/tcp": null
                }
            }
        });
        let tunnel_ext: Arc<dyn SandboxTunnelPort> = Arc::new(MockTcpTunnelPort {
            expected_guest_port: 49001,
            half_close_mode: false,
        });
        let ext_fwds = reg
            .activate_container_forwards(
                tunnel_ext,
                &sbx_id,
                "1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff",
                &ext_inspect,
            )
            .await
            .unwrap();
        assert_eq!(ext_fwds.len(), 1);
        assert_eq!(ext_fwds[0].container_key, "80/tcp");
        assert_eq!(ext_fwds[0].guest_port, 49001);

        // Case 2: Fixed host port survives restart even when guest port changes.
        let cid = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";
        reg.record_create(
            cid,
            Some("fixed-app"),
            vec![RequestedPortBinding {
                container_port: 8080,
                protocol: "tcp".to_owned(),
                host_port: Some(fixed_host_port),
                container_key: "8080/tcp".to_owned(),
            }],
        );
        let inspect_1 = json!({
            "Id": cid,
            "NetworkSettings": { "Ports": { "8080/tcp": [{ "HostIp": "127.0.0.1", "HostPort": "41001" }] } }
        });
        let tunnel_1: Arc<dyn SandboxTunnelPort> = Arc::new(MockTcpTunnelPort {
            expected_guest_port: 41001,
            half_close_mode: false,
        });
        let f1 = reg
            .activate_container_forwards(tunnel_1, &sbx_id, cid, &inspect_1)
            .await
            .unwrap();
        assert_eq!(f1[0].host_port, fixed_host_port);

        let inspect_2 = json!({
            "Id": cid,
            "NetworkSettings": { "Ports": { "8080/tcp": [{ "HostIp": "127.0.0.1", "HostPort": "41002" }] } }
        });
        let tunnel_2: Arc<dyn SandboxTunnelPort> = Arc::new(MockTcpTunnelPort {
            expected_guest_port: 41002,
            half_close_mode: false,
        });
        let f2 = reg
            .activate_container_forwards(tunnel_2, &sbx_id, cid, &inspect_2)
            .await
            .unwrap();
        assert_eq!(f2[0].host_port, fixed_host_port);
        assert_eq!(f2[0].guest_port, 41002);

        let mut stream = TcpStream::connect(("127.0.0.1", fixed_host_port))
            .await
            .unwrap();
        stream.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");
    }

    #[tokio::test]
    async fn release_closes_active_idle_forwarded_connections_and_caps_concurrency() {
        use tokio::io::AsyncReadExt;

        let cid = "222233334444555566667777888899990000aaaabbbbccccddddeeeeffff1111";
        let reg = PortForwardRegistry::new();
        let sbx_id = SandboxId::new("sbx-port-bounds");
        let inspect = json!({
            "Id": cid,
            "NetworkSettings": {
                "Ports": {
                    "80/tcp": [{ "HostIp": "127.0.0.1", "HostPort": "45080" }]
                }
            }
        });
        let tunnel: Arc<dyn SandboxTunnelPort> = Arc::new(MockTcpTunnelPort {
            expected_guest_port: 45080,
            half_close_mode: false,
        });
        let fwds = reg
            .activate_container_forwards(tunnel, &sbx_id, cid, &inspect)
            .await
            .expect("activate bounded forwards");
        let host_port = fwds[0].host_port;

        // Open `MAX_CONCURRENT_PORT_FORWARD_CONNS` active connections and verify they echo.
        let mut open_clients = Vec::with_capacity(MAX_CONCURRENT_PORT_FORWARD_CONNS);
        for _ in 0..MAX_CONCURRENT_PORT_FORWARD_CONNS {
            let mut client = TcpStream::connect(("127.0.0.1", host_port)).await.unwrap();
            client.write_all(b"ok").await.unwrap();
            let mut pong = [0u8; 2];
            client.read_exact(&mut pong).await.unwrap();
            assert_eq!(&pong, b"ok");
            open_clients.push(client);
        }

        // Excess (65th) concurrent connection must be closed promptly instead of spawning unboundedly.
        let mut excess = TcpStream::connect(("127.0.0.1", host_port)).await.unwrap();
        let mut probe = [0u8; 16];
        let excess_res = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            excess.read(&mut probe),
        )
        .await
        .expect("excess connection must be closed promptly");
        assert!(
            matches!(excess_res, Ok(0) | Err(_)),
            "expected excess connection EOF/reset, got {excess_res:?}"
        );

        // Existing idle connections must still function, then close immediately on release.
        open_clients[0].write_all(b"hi").await.unwrap();
        let mut echo = [0u8; 2];
        open_clients[0].read_exact(&mut echo).await.unwrap();
        assert_eq!(&echo, b"hi");

        reg.release_container_forwards_async(cid, true).await;
        let close_res = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            open_clients[0].read(&mut probe),
        )
        .await
        .expect("active forwarded connection must close on container release");
        assert!(
            matches!(close_res, Ok(0) | Err(_)),
            "expected EOF/reset after release, got {close_res:?}"
        );
    }
}
