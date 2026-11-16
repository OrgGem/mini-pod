//! Host Egress Proxy enforcing [`NetworkPolicy`] with IPv4/IPv6 bogon filtering,
//! pre-DNS allowlist checks, anti-DNS-rebinding direct-IP dialing, and HTTP redirect re-validation.

use std::io::{self, ErrorKind};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use sandbox_core::{domain_matches_rule, normalize_egress_domain, NetworkPolicy};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;

const MAX_HTTP_HEAD_BYTES: usize = 64 * 1024;
const MAX_HEADER_COUNT: usize = 128;
const MAX_CHUNK_LINE_BYTES: usize = 4096;
const STREAM_COPY_BUF_BYTES: usize = 16 * 1024;
const DEFAULT_UPSTREAM_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const DEFAULT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);
const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(120);

/// Returns `true` if `ip` belongs to any non-global, private, loopback, link-local,
/// multicast, reserved, documentation, or tunneled/mapped special-purpose range.
pub fn is_forbidden_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_forbidden_ipv4(v4),
        IpAddr::V6(v6) => is_forbidden_ipv6(v6),
    }
}

/// Returns `true` if `ip` belongs to any non-global or special-purpose IPv4 CIDR.
pub fn is_forbidden_ipv4(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    o[0] == 0 // 0.0.0.0/8 ("this network")
        || o[0] == 10 // 10.0.0.0/8 (RFC 1918)
        || (o[0] == 100 && (64..=127).contains(&o[1])) // 100.64.0.0/10 (CGNAT)
        || o[0] == 127 // 127.0.0.0/8 (loopback)
        || (o[0] == 169 && o[1] == 254) // 169.254.0.0/16 (link-local / metadata)
        || (o[0] == 172 && (16..=31).contains(&o[1])) // 172.16.0.0/12 (RFC 1918)
        || (o[0] == 192 && o[1] == 0 && o[2] == 0) // 192.0.0.0/24 (IETF protocol)
        || (o[0] == 192 && o[1] == 0 && o[2] == 2) // 192.0.2.0/24 (TEST-NET-1)
        || (o[0] == 192 && o[1] == 88 && o[2] == 99) // 192.88.99.0/24 (6to4 relay)
        || (o[0] == 192 && o[1] == 168) // 192.168.0.0/16 (RFC 1918)
        || (o[0] == 198 && (18..=19).contains(&o[1])) // 198.18.0.0/15 (benchmarking)
        || (o[0] == 198 && o[1] == 51 && o[2] == 100) // 198.51.100.0/24 (TEST-NET-2)
        || (o[0] == 203 && o[1] == 0 && o[2] == 113) // 203.0.113.0/24 (TEST-NET-3)
        || o[0] >= 224 // 224.0.0.0/4 (multicast) + 240.0.0.0/4 (reserved/broadcast)
}

/// Returns `true` if `ip` belongs to any non-global, special-purpose, or forbidden-embedded IPv6 CIDR.
pub fn is_forbidden_ipv6(ip: Ipv6Addr) -> bool {
    let seg = ip.segments();
    let b = ip.octets();

    // ::/128, ::1/128, and ::/96 (IPv4-compatible deprecated block)
    if seg[..6] == [0, 0, 0, 0, 0, 0] {
        return true;
    }
    // ::ffff:0:0/96 (IPv4-mapped IPv6): extract trailing IPv4 and check it
    if seg[..5] == [0, 0, 0, 0, 0] && seg[5] == 0xffff {
        return is_forbidden_ipv4(Ipv4Addr::new(b[12], b[13], b[14], b[15]));
    }
    // ::ffff:0:0:0/96 (IPv4-translated SIIT)
    if seg[..4] == [0, 0, 0, 0] && seg[4] == 0xffff && seg[5] == 0 {
        return true;
    }
    // 64:ff9b::/96 (NAT64 well-known): extract trailing IPv4 and check it
    if seg[..6] == [0x0064, 0xff9b, 0, 0, 0, 0] {
        return is_forbidden_ipv4(Ipv4Addr::new(b[12], b[13], b[14], b[15]));
    }
    // 64:ff9b:1::/48 (NAT64 local-use)
    if seg[..3] == [0x0064, 0xff9b, 0x0001] {
        return true;
    }
    // 2002::/16 (6to4): extract embedded IPv4 from bytes 2..6 (segments 1..3) and check it
    if seg[0] == 0x2002 {
        return is_forbidden_ipv4(Ipv4Addr::new(b[2], b[3], b[4], b[5]));
    }
    // 2001::/32 (Teredo)
    if seg[0] == 0x2001 && seg[1] == 0x0000 {
        return true;
    }
    // 100::/64 (Discard-only)
    if seg[..4] == [0x0100, 0, 0, 0] {
        return true;
    }
    // 2001:2::/48 (Benchmarking)
    if seg[..3] == [0x2001, 0x0002, 0] {
        return true;
    }
    // 2001:db8::/32 (Documentation)
    if seg[0] == 0x2001 && seg[1] == 0x0db8 {
        return true;
    }
    // fc00::/7 (Unique Local Addresses)
    if (b[0] & 0xfe) == 0xfc {
        return true;
    }
    // fe80::/10 (Link-local) and fec0::/10 (Deprecated site-local)
    if (seg[0] & 0xffc0) == 0xfe80 || (seg[0] & 0xffc0) == 0xfec0 {
        return true;
    }
    // ff00::/8 (Multicast)
    if b[0] == 0xff {
        return true;
    }
    false
}

/// Asynchronous bidirectional byte stream returned by [`UpstreamDialer`].
pub trait AsyncStream: AsyncRead + AsyncWrite + Send {}

impl<T: AsyncRead + AsyncWrite + Send> AsyncStream for T {}

/// Pinned boxed upstream stream returned by [`UpstreamDialer::connect`].
pub type BoxedUpstreamStream = Pin<Box<dyn AsyncStream>>;

/// Host-side DNS resolution port used prior to direct-IP dialing.
#[async_trait::async_trait]
pub trait HostDnsResolver: Send + Sync {
    async fn resolve(&self, host: &str, port: u16) -> io::Result<Vec<SocketAddr>>;
}

/// Default [`HostDnsResolver`] backed by `tokio::net::lookup_host`.
#[derive(Clone, Debug, Default)]
pub struct SystemDnsResolver;

#[async_trait::async_trait]
impl HostDnsResolver for SystemDnsResolver {
    async fn resolve(&self, host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
        Ok(tokio::net::lookup_host((host, port)).await?.collect())
    }
}

/// Host-side TCP dialer port that MUST ONLY be invoked with pre-validated [`SocketAddr`] values.
#[async_trait::async_trait]
pub trait UpstreamDialer: Send + Sync {
    async fn connect(&self, addr: SocketAddr) -> io::Result<BoxedUpstreamStream>;
}

/// Default [`UpstreamDialer`] connecting directly to a validated [`SocketAddr`].
#[derive(Clone, Debug, Default)]
pub struct TcpUpstreamDialer;

#[async_trait::async_trait]
impl UpstreamDialer for TcpUpstreamDialer {
    async fn connect(&self, addr: SocketAddr) -> io::Result<BoxedUpstreamStream> {
        let stream = tokio::time::timeout(DEFAULT_UPSTREAM_CONNECT_TIMEOUT, TcpStream::connect(addr))
            .await
            .map_err(|_| io::Error::new(ErrorKind::TimedOut, "upstream TCP connect timed out"))??;
        let _ = stream.set_nodelay(true);
        Ok(Box::pin(stream))
    }
}

struct ActivityTracker {
    origin: Instant,
    last_active_ns: AtomicU64,
    connected: AtomicBool,
}

impl ActivityTracker {
    fn new() -> Self {
        Self {
            origin: Instant::now(),
            last_active_ns: AtomicU64::new(0),
            connected: AtomicBool::new(false),
        }
    }

    fn record_activity(&self) {
        let ns = u64::try_from(self.origin.elapsed().as_nanos()).unwrap_or(u64::MAX);
        self.last_active_ns.store(ns, Ordering::Release);
    }

    fn mark_connected(&self) {
        self.record_activity();
        self.connected.store(true, Ordering::Release);
    }

    async fn wait_until_expired(&self, handshake_timeout: Duration, idle_timeout: Duration) {
        loop {
            if !self.connected.load(Ordering::Acquire) {
                let elapsed = self.origin.elapsed();
                if elapsed >= handshake_timeout {
                    return;
                }
                let remaining = handshake_timeout.saturating_sub(elapsed);
                tokio::time::sleep(remaining.min(idle_timeout).max(Duration::from_millis(5))).await;
            } else {
                let last = Duration::from_nanos(self.last_active_ns.load(Ordering::Acquire));
                let idle = self.origin.elapsed().saturating_sub(last);
                if idle >= idle_timeout {
                    return;
                }
                tokio::time::sleep((idle_timeout - idle).max(Duration::from_millis(5))).await;
            }
        }
    }
}

struct TrackedIo<S> {
    inner: S,
    tracker: Arc<ActivityTracker>,
}

impl<S> TrackedIo<S> {
    fn new(inner: S, tracker: Arc<ActivityTracker>) -> Self {
        Self { inner, tracker }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for TrackedIo<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        let poll = Pin::new(&mut this.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &poll {
            if buf.filled().len() > before {
                this.tracker.record_activity();
            }
        }
        poll
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for TrackedIo<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let poll = Pin::new(&mut this.inner).poll_write(cx, data);
        if let Poll::Ready(Ok(n)) = &poll {
            if *n > 0 {
                this.tracker.record_activity();
            }
        }
        poll
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

/// Host-side HTTP (`CONNECT` + forward) and SOCKS5 (`CONNECT` only) egress proxy.
#[derive(Clone)]
pub struct HostEgressProxy {
    policy: NetworkPolicy,
    dns: Arc<dyn HostDnsResolver>,
    dialer: Arc<dyn UpstreamDialer>,
    handshake_timeout: Duration,
    idle_timeout: Duration,
}

impl HostEgressProxy {
    /// Builds a [`HostEgressProxy`] enforcing `policy` via `dns` and `dialer`.
    pub fn new(
        policy: NetworkPolicy,
        dns: Arc<dyn HostDnsResolver>,
        dialer: Arc<dyn UpstreamDialer>,
    ) -> Self {
        Self::with_timeouts(
            policy,
            dns,
            dialer,
            DEFAULT_HANDSHAKE_TIMEOUT,
            DEFAULT_IDLE_TIMEOUT,
        )
    }

    /// Builds a [`HostEgressProxy`] with explicit handshake and post-connect idle timeouts.
    pub fn with_timeouts(
        policy: NetworkPolicy,
        dns: Arc<dyn HostDnsResolver>,
        dialer: Arc<dyn UpstreamDialer>,
        handshake_timeout: Duration,
        idle_timeout: Duration,
    ) -> Self {
        Self {
            policy,
            dns,
            dialer,
            handshake_timeout: handshake_timeout.max(Duration::from_millis(1)),
            idle_timeout: idle_timeout.max(Duration::from_millis(1)),
        }
    }

    /// Returns the active [`NetworkPolicy`] enforced by this proxy.
    pub fn policy(&self) -> &NetworkPolicy {
        &self.policy
    }

    /// Handles a single client stream (SOCKS5 if first byte is `0x05`, otherwise HTTP proxy).
    pub async fn handle_stream<S>(&self, mut stream: S)
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        if matches!(self.policy, NetworkPolicy::Isolated) {
            let _ = stream.shutdown().await;
            return;
        }

        let tracker = Arc::new(ActivityTracker::new());
        let mut tracked = TrackedIo::new(&mut stream, Arc::clone(&tracker));
        let handshake_timeout = self.handshake_timeout;
        let idle_timeout = self.idle_timeout;

        let completed = tokio::select! {
            biased;
            () = tracker.wait_until_expired(handshake_timeout, idle_timeout) => false,
            () = self.handle_tracked_stream(&mut tracked, Arc::clone(&tracker)) => true,
        };
        if !completed {
            let _ = stream.shutdown().await;
        }
    }

    async fn handle_tracked_stream<S>(&self, mut stream: S, tracker: Arc<ActivityTracker>)
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        let mut first = [0u8; 1];
        match stream.read(&mut first).await {
            Ok(0) | Err(_) => return,
            Ok(_) => {}
        }

        if first[0] == 0x05 {
            self.handle_socks5(stream, tracker).await;
        } else {
            let prefixed = PrefixedStream::with_prefix(stream, vec![first[0]]);
            self.handle_http(prefixed, tracker).await;
        }
    }

    async fn validate_and_resolve(
        &self,
        host: &TargetHost,
        port: u16,
    ) -> Result<Vec<SocketAddr>, EgressReject> {
        if port == 0 {
            return Err(EgressReject::Forbidden("destination port cannot be 0"));
        }

        match &self.policy {
            NetworkPolicy::Isolated => Err(EgressReject::Forbidden("network policy is Isolated")),
            NetworkPolicy::DomainAllowList { rules } => {
                let domain = match host {
                    TargetHost::Ip(_) => {
                        return Err(EgressReject::Forbidden(
                            "raw IP literals are forbidden under DomainAllowList",
                        ));
                    }
                    TargetHost::Domain(domain) => domain,
                };
                let allowed = rules.iter().any(|rule| {
                    rule.port > 0
                        && rule.port == port
                        && domain_matches_rule(&rule.domain, domain)
                });
                if !allowed {
                    return Err(EgressReject::Forbidden(
                        "destination domain/port is not in DomainAllowList",
                    ));
                }
                self.resolve_and_filter_non_global(domain, port).await
            }
            NetworkPolicy::InternetOnly => match host {
                TargetHost::Ip(ip) => {
                    if is_forbidden_ip(*ip) {
                        Err(EgressReject::Forbidden(
                            "destination IP is in a forbidden non-global range",
                        ))
                    } else {
                        Ok(vec![SocketAddr::new(*ip, port)])
                    }
                }
                TargetHost::Domain(domain) => {
                    self.resolve_and_filter_non_global(domain, port).await
                }
            },
            NetworkPolicy::Unrestricted => match host {
                TargetHost::Ip(ip) => Ok(vec![SocketAddr::new(*ip, port)]),
                TargetHost::Domain(domain) => {
                    let addrs = self
                        .dns
                        .resolve(domain, port)
                        .await
                        .map_err(|_| EgressReject::ResolveFailed)?;
                    if addrs.is_empty() {
                        return Err(EgressReject::ResolveFailed);
                    }
                    Ok(addrs
                        .into_iter()
                        .map(|addr| SocketAddr::new(addr.ip(), port))
                        .collect())
                }
            },
        }
    }

    async fn resolve_and_filter_non_global(
        &self,
        domain: &str,
        port: u16,
    ) -> Result<Vec<SocketAddr>, EgressReject> {
        let addrs = self
            .dns
            .resolve(domain, port)
            .await
            .map_err(|_| EgressReject::ResolveFailed)?;
        if addrs.is_empty() {
            return Err(EgressReject::Forbidden("DNS resolution returned no addresses"));
        }
        // Reject the entire lookup if ANY returned IP is non-global to defeat mixed/rebinding replies.
        if addrs.iter().any(|addr| is_forbidden_ip(addr.ip())) {
            return Err(EgressReject::Forbidden(
                "DNS resolution yielded a forbidden non-global IP address",
            ));
        }
        Ok(addrs
            .into_iter()
            .map(|addr| SocketAddr::new(addr.ip(), port))
            .collect())
    }

    async fn connect_validated(
        &self,
        addrs: &[SocketAddr],
        tracker: &Arc<ActivityTracker>,
    ) -> io::Result<TrackedIo<BoxedUpstreamStream>> {
        let mut last_err = None;
        for &addr in addrs {
            match self.dialer.connect(addr).await {
                Ok(stream) => {
                    tracker.mark_connected();
                    return Ok(TrackedIo::new(stream, Arc::clone(tracker)));
                }
                Err(err) => last_err = Some(err),
            }
        }
        Err(last_err.unwrap_or_else(|| {
            io::Error::new(ErrorKind::AddrNotAvailable, "no validated upstream address")
        }))
    }

    async fn handle_socks5<S>(&self, mut stream: S, tracker: Arc<ActivityTracker>)
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        let mut nmethods_buf = [0u8; 1];
        if stream.read_exact(&mut nmethods_buf).await.is_err() {
            return;
        }
        let nmethods = nmethods_buf[0] as usize;
        if nmethods == 0 {
            let _ = write_and_flush(&mut stream, &[0x05, 0xFF]).await;
            return;
        }
        let mut methods = vec![0u8; nmethods];
        if stream.read_exact(&mut methods).await.is_err() {
            return;
        }
        if !methods.contains(&0x00) {
            let _ = write_and_flush(&mut stream, &[0x05, 0xFF]).await;
            return;
        }
        if write_and_flush(&mut stream, &[0x05, 0x00]).await.is_err() {
            return;
        }

        let mut hdr = [0u8; 4];
        if stream.read_exact(&mut hdr).await.is_err() {
            return;
        }
        let [ver, cmd, rsv, atyp] = hdr;
        if ver != 0x05 || rsv != 0x00 {
            let _ = send_socks5_reply(&mut stream, 0x01).await;
            return;
        }

        let target_host = match atyp {
            0x01 => {
                let mut octets = [0u8; 4];
                if stream.read_exact(&mut octets).await.is_err() {
                    return;
                }
                Ok(TargetHost::Ip(IpAddr::V4(Ipv4Addr::from(octets))))
            }
            0x03 => {
                let mut len_buf = [0u8; 1];
                if stream.read_exact(&mut len_buf).await.is_err() {
                    return;
                }
                let len = len_buf[0] as usize;
                if len == 0 {
                    let _ = send_socks5_reply(&mut stream, 0x01).await;
                    return;
                }
                let mut raw = vec![0u8; len];
                if stream.read_exact(&mut raw).await.is_err() {
                    return;
                }
                match std::str::from_utf8(&raw) {
                    Ok(host_str) => parse_socks5_host(host_str).map_err(|_| ()),
                    Err(_) => Err(()),
                }
            }
            0x04 => {
                let mut octets = [0u8; 16];
                if stream.read_exact(&mut octets).await.is_err() {
                    return;
                }
                Ok(TargetHost::Ip(IpAddr::V6(Ipv6Addr::from(octets))))
            }
            _ => {
                let _ = send_socks5_reply(&mut stream, 0x08).await;
                return;
            }
        };

        let mut port_buf = [0u8; 2];
        if stream.read_exact(&mut port_buf).await.is_err() {
            return;
        }
        let port = u16::from_be_bytes(port_buf);

        // Explicitly reject BIND (0x02), UDP ASSOCIATE (0x03), or unknown commands with 0x07.
        if cmd != 0x01 {
            let _ = send_socks5_reply(&mut stream, 0x07).await;
            return;
        }

        let Ok(target_host) = target_host else {
            let _ = send_socks5_reply(&mut stream, 0x01).await;
            return;
        };

        let addrs = match self.validate_and_resolve(&target_host, port).await {
            Ok(addrs) => addrs,
            Err(EgressReject::Forbidden(_)) => {
                let _ = send_socks5_reply(&mut stream, 0x02).await;
                return;
            }
            Err(EgressReject::ResolveFailed) => {
                let _ = send_socks5_reply(&mut stream, 0x04).await;
                return;
            }
        };

        let mut upstream = match self.connect_validated(&addrs, &tracker).await {
            Ok(up) => up,
            Err(err) => {
                let code = match err.kind() {
                    ErrorKind::ConnectionRefused => 0x05,
                    ErrorKind::TimedOut => 0x06,
                    _ => 0x04,
                };
                let _ = send_socks5_reply(&mut stream, code).await;
                return;
            }
        };

        if send_socks5_reply(&mut stream, 0x00).await.is_err() {
            return;
        }
        let _ = tokio::io::copy_bidirectional(&mut stream, &mut upstream).await;
        let _ = upstream.shutdown().await;
        let _ = stream.shutdown().await;
    }

    async fn handle_http<S>(&self, mut client: PrefixedStream<S>, tracker: Arc<ActivityTracker>)
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        let raw_head = match read_http_head_bytes(&mut client, true).await {
            Ok(Some(bytes)) => bytes,
            Ok(None) => return,
            Err(HttpHeadError::TooLarge) => {
                let _ = write_http_error(
                    &mut client,
                    431,
                    "Request Header Fields Too Large",
                    "request headers too large",
                )
                .await;
                return;
            }
            Err(_) => {
                let _ = write_http_error(&mut client, 400, "Bad Request", "malformed HTTP head")
                    .await;
                return;
            }
        };

        let req = match parse_http_request_head(&raw_head) {
            Ok(req) => req,
            Err(msg) => {
                let _ = write_http_error(&mut client, 400, "Bad Request", msg).await;
                return;
            }
        };

        if req.method == "CONNECT" {
            self.handle_http_connect(client, req, tracker).await;
        } else if is_supported_forward_method(&req.method) {
            self.handle_http_forward(client, req, tracker).await;
        } else {
            let _ = write_http_error(
                &mut client,
                405,
                "Method Not Allowed",
                "unsupported HTTP method",
            )
            .await;
        }
    }

    async fn handle_http_connect<S>(
        &self,
        mut client: PrefixedStream<S>,
        req: HttpRequestHead,
        tracker: Arc<ActivityTracker>,
    ) where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        if req.body_mode != BodyMode::Empty {
            let _ = write_http_error(
                &mut client,
                400,
                "Bad Request",
                "CONNECT request must not include a message body",
            )
            .await;
            return;
        }

        if req.raw_target.contains('@')
            || req.raw_target.contains('/')
            || req.raw_target.contains('?')
            || req.raw_target.contains('#')
            || req.raw_target.contains("://")
        {
            let _ = write_http_error(&mut client, 400, "Bad Request", "invalid CONNECT target")
                .await;
            return;
        }

        let Ok((target_host, port)) = parse_authority(&req.raw_target, None) else {
            let _ = write_http_error(&mut client, 400, "Bad Request", "invalid CONNECT authority")
                .await;
            return;
        };

        if !host_header_matches(&req.headers, &target_host, port) {
            let _ = write_http_error(
                &mut client,
                400,
                "Bad Request",
                "Host header conflicts with CONNECT target",
            )
            .await;
            return;
        }

        let addrs = match self.validate_and_resolve(&target_host, port).await {
            Ok(addrs) => addrs,
            Err(EgressReject::Forbidden(msg)) => {
                let _ = write_http_error(&mut client, 403, "Forbidden", msg).await;
                return;
            }
            Err(EgressReject::ResolveFailed) => {
                let _ = write_http_error(
                    &mut client,
                    502,
                    "Bad Gateway",
                    "DNS resolution failed",
                )
                .await;
                return;
            }
        };

        let mut upstream = match self.connect_validated(&addrs, &tracker).await {
            Ok(up) => up,
            Err(_) => {
                let _ = write_http_error(
                    &mut client,
                    502,
                    "Bad Gateway",
                    "upstream connection failed",
                )
                .await;
                return;
            }
        };

        if write_and_flush(&mut client, b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await
            .is_err()
        {
            return;
        }

        let trailing = client.take_buffered();
        if !trailing.is_empty()
            && write_and_flush(&mut upstream, &trailing).await.is_err()
        {
            return;
        }

        let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
        let _ = upstream.shutdown().await;
        let _ = client.shutdown().await;
    }

    async fn handle_http_forward<S>(
        &self,
        mut client: PrefixedStream<S>,
        req: HttpRequestHead,
        tracker: Arc<ActivityTracker>,
    ) where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        let parsed_target = match parse_proxy_http_url(&req.raw_target) {
            Ok(target) => target,
            Err(msg) => {
                let _ = write_http_error(&mut client, 400, "Bad Request", msg).await;
                return;
            }
        };

        if !host_header_matches(&req.headers, &parsed_target.host, parsed_target.port) {
            let _ = write_http_error(
                &mut client,
                400,
                "Bad Request",
                "Host header conflicts with request target",
            )
            .await;
            return;
        }

        let addrs = match self
            .validate_and_resolve(&parsed_target.host, parsed_target.port)
            .await
        {
            Ok(addrs) => addrs,
            Err(EgressReject::Forbidden(msg)) => {
                let _ = write_http_error(&mut client, 403, "Forbidden", msg).await;
                return;
            }
            Err(EgressReject::ResolveFailed) => {
                let _ = write_http_error(
                    &mut client,
                    502,
                    "Bad Gateway",
                    "DNS resolution failed",
                )
                .await;
                return;
            }
        };

        let upstream_stream = match self.connect_validated(&addrs, &tracker).await {
            Ok(up) => up,
            Err(_) => {
                let _ = write_http_error(
                    &mut client,
                    502,
                    "Bad Gateway",
                    "upstream connection failed",
                )
                .await;
                return;
            }
        };

        let mut upstream = PrefixedStream::new(upstream_stream);
        let serialized_req = build_upstream_request_head(
            &req.method,
            &parsed_target.origin_form,
            &parsed_target.host,
            parsed_target.port,
            &req.headers,
        );
        if upstream.write_all(&serialized_req).await.is_err() {
            let _ = write_http_error(&mut client, 502, "Bad Gateway", "upstream write failed")
                .await;
            return;
        }
        if forward_body(&mut client, &mut upstream, req.body_mode)
            .await
            .is_err()
        {
            let _ = write_http_error(
                &mut client,
                400,
                "Bad Request",
                "failed to forward request body",
            )
            .await;
            return;
        }
        if upstream.flush().await.is_err() {
            let _ = write_http_error(&mut client, 502, "Bad Gateway", "upstream flush failed")
                .await;
            return;
        }

        let resp = loop {
            let raw_resp_head = match read_http_head_bytes(&mut upstream, false).await {
                Ok(Some(bytes)) => bytes,
                Ok(None) | Err(_) => {
                    let _ = write_http_error(
                        &mut client,
                        502,
                        "Bad Gateway",
                        "invalid or truncated upstream response head",
                    )
                    .await;
                    return;
                }
            };
            let head = match parse_http_response_head(&raw_resp_head) {
                Ok(head) => head,
                Err(_) => {
                    let _ = write_http_error(
                        &mut client,
                        502,
                        "Bad Gateway",
                        "malformed upstream response headers",
                    )
                    .await;
                    return;
                }
            };
            if (100..=199).contains(&head.status) {
                if head.status == 101 {
                    let _ = write_http_error(
                        &mut client,
                        502,
                        "Bad Gateway",
                        "protocol upgrade is not permitted on HTTP forward proxy",
                    )
                    .await;
                    return;
                }
                let info_bytes = build_client_response_head(&head, false);
                if write_and_flush(&mut client, &info_bytes).await.is_err() {
                    return;
                }
                continue;
            }
            break head;
        };

        if (300..=399).contains(&resp.status) {
            if let Err(err) = self
                .validate_redirect_headers(&resp.headers, &parsed_target.host, parsed_target.port)
                .await
            {
                drop(upstream);
                match err {
                    EgressReject::Forbidden(msg) => {
                        let _ = write_http_error(&mut client, 403, "Forbidden", msg).await;
                    }
                    EgressReject::ResolveFailed => {
                        let _ = write_http_error(
                            &mut client,
                            502,
                            "Bad Gateway",
                            "redirect DNS resolution failed",
                        )
                        .await;
                    }
                }
                return;
            }
        }

        let resp_body_mode = if req.method == "HEAD" || matches!(resp.status, 204 | 304) {
            BodyMode::Empty
        } else {
            resp.body_mode
        };

        let resp_bytes = build_client_response_head(&resp, true);
        if client.write_all(&resp_bytes).await.is_err() {
            return;
        }
        if forward_body(&mut upstream, &mut client, resp_body_mode)
            .await
            .is_err()
        {
            let _ = client.shutdown().await;
            return;
        }
        let _ = client.flush().await;
        let _ = client.shutdown().await;
    }

    async fn validate_redirect_headers(
        &self,
        headers: &[(String, String)],
        origin_host: &TargetHost,
        origin_port: u16,
    ) -> Result<(), EgressReject> {
        let locations: Vec<&str> = headers
            .iter()
            .filter(|(name, _)| name.eq_ignore_ascii_case("location"))
            .map(|(_, val)| val.as_str())
            .collect();
        if locations.is_empty() {
            return Ok(());
        }
        if locations.len() > 1 {
            return Err(EgressReject::Forbidden(
                "ambiguous multiple Location headers in redirect response",
            ));
        }

        let loc = locations[0];
        if loc.is_empty()
            || loc.bytes().any(|b| b.is_ascii_whitespace() || b.is_ascii_control())
            || loc.starts_with('\\')
            || loc.starts_with("/\\")
        {
            return Err(EgressReject::Forbidden(
                "invalid Location redirect target",
            ));
        }

        // Scheme-relative URL (`//host/...`) inherits `http` (port 80) and must be validated.
        if let Some(after_slashes) = loc.strip_prefix("//") {
            let (host, port) = parse_redirect_authority(after_slashes, 80)?;
            let _ = self.validate_and_resolve(&host, port).await?;
            return Ok(());
        }

        // Explicit scheme (`scheme:...`) before any path/query/fragment delimiter.
        let before_delim = loc.split(['/', '?', '#']).next().unwrap_or(loc);
        if let Some((scheme, _)) = before_delim.split_once(':') {
            if is_valid_uri_scheme(scheme) {
                let default_port = if scheme.eq_ignore_ascii_case("http") {
                    80
                } else if scheme.eq_ignore_ascii_case("https") {
                    443
                } else {
                    return Err(EgressReject::Forbidden(
                        "redirect uses disallowed URI scheme",
                    ));
                };
                let after_colon = &loc[scheme.len() + 1..];
                let after_slashes = after_colon.strip_prefix("//").ok_or(EgressReject::Forbidden(
                    "redirect URI missing '//' authority",
                ))?;
                let (host, port) = parse_redirect_authority(after_slashes, default_port)?;
                let _ = self.validate_and_resolve(&host, port).await?;
                return Ok(());
            }
        }

        // Relative path/query/fragment stays on the already-validated origin host and port.
        let _ = (origin_host, origin_port);
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum TargetHost {
    Ip(IpAddr),
    Domain(String),
}

enum EgressReject {
    Forbidden(&'static str),
    ResolveFailed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BodyMode {
    Empty,
    ContentLength(u64),
    Chunked,
    UntilEof,
}

#[derive(Debug)]
struct ParsedHttpHeaders {
    headers: Vec<(String, String)>,
    body_mode: BodyMode,
}

#[derive(Debug)]
struct HttpRequestHead {
    method: String,
    raw_target: String,
    headers: Vec<(String, String)>,
    body_mode: BodyMode,
}

#[derive(Debug)]
struct HttpResponseHead {
    version: String,
    status: u16,
    reason: String,
    headers: Vec<(String, String)>,
    body_mode: BodyMode,
}

struct ParsedProxyHttpUrl {
    host: TargetHost,
    port: u16,
    origin_form: String,
}

enum HttpHeadError {
    TooLarge,
    Malformed,
    Io,
}

struct PrefixedStream<S> {
    inner: S,
    buf: Vec<u8>,
    pos: usize,
}

impl<S> PrefixedStream<S> {
    fn new(inner: S) -> Self {
        Self {
            inner,
            buf: Vec::new(),
            pos: 0,
        }
    }

    fn with_prefix(inner: S, prefix: Vec<u8>) -> Self {
        Self {
            inner,
            buf: prefix,
            pos: 0,
        }
    }

    fn buffered_slice(&self) -> &[u8] {
        &self.buf[self.pos..]
    }

    fn take_buffered(&mut self) -> Vec<u8> {
        if self.pos >= self.buf.len() {
            self.buf.clear();
            self.pos = 0;
            return Vec::new();
        }
        let out = self.buf[self.pos..].to_vec();
        self.buf.clear();
        self.pos = 0;
        out
    }

    async fn read_line_crlf(&mut self, max_len: usize) -> io::Result<String>
    where
        S: AsyncRead + Unpin,
    {
        loop {
            let avail = self.buffered_slice();
            if let Some(rel_end) = avail.windows(2).position(|w| w == b"\r\n") {
                if rel_end > max_len {
                    return Err(io::Error::new(
                        ErrorKind::InvalidData,
                        "chunk line exceeds maximum length",
                    ));
                }
                let line = std::str::from_utf8(&avail[..rel_end])
                    .map_err(|_| io::Error::new(ErrorKind::InvalidData, "non-UTF-8 line"))?
                    .to_owned();
                self.pos += rel_end + 2;
                if self.pos == self.buf.len() {
                    self.buf.clear();
                    self.pos = 0;
                }
                return Ok(line);
            }
            if avail.len() > max_len {
                return Err(io::Error::new(
                    ErrorKind::InvalidData,
                    "chunk line exceeds maximum length",
                ));
            }
            if self.pos > 0 {
                self.buf.drain(..self.pos);
                self.pos = 0;
            }
            let mut tmp = [0u8; 512];
            let n = self.inner.read(&mut tmp).await?;
            if n == 0 {
                return Err(io::Error::new(ErrorKind::UnexpectedEof, "unexpected EOF"));
            }
            self.buf.extend_from_slice(&tmp[..n]);
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for PrefixedStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.pos < this.buf.len() {
            let n = out.remaining().min(this.buf.len() - this.pos);
            out.put_slice(&this.buf[this.pos..this.pos + n]);
            this.pos += n;
            if this.pos == this.buf.len() {
                this.buf.clear();
                this.pos = 0;
            }
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.inner).poll_read(cx, out)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PrefixedStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, data)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

async fn read_http_head_bytes<S: AsyncRead + Unpin>(
    stream: &mut PrefixedStream<S>,
    allow_clean_eof: bool,
) -> Result<Option<Vec<u8>>, HttpHeadError> {
    loop {
        let avail = stream.buffered_slice();
        if let Some(rel_end) = avail.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = avail[..rel_end].to_vec();
            stream.pos += rel_end + 4;
            if stream.pos == stream.buf.len() {
                stream.buf.clear();
                stream.pos = 0;
            }
            return Ok(Some(head));
        }
        if avail.len() >= MAX_HTTP_HEAD_BYTES {
            return Err(HttpHeadError::TooLarge);
        }
        if stream.pos > 0 {
            stream.buf.drain(..stream.pos);
            stream.pos = 0;
        }

        let max_read = (MAX_HTTP_HEAD_BYTES - stream.buf.len()).min(4096);
        let mut tmp = [0u8; 4096];
        let n = stream
            .inner
            .read(&mut tmp[..max_read])
            .await
            .map_err(|_| HttpHeadError::Io)?;
        if n == 0 {
            if allow_clean_eof && stream.buf.is_empty() {
                return Ok(None);
            }
            return Err(HttpHeadError::Malformed);
        }
        stream.buf.extend_from_slice(&tmp[..n]);
    }
}

fn split_crlf_lines(raw: &[u8]) -> Result<Vec<&[u8]>, &'static str> {
    if raw.is_empty() || raw.contains(&b'\0') {
        return Err("empty or NUL-containing HTTP head");
    }
    let mut lines = Vec::new();
    let mut start = 0usize;
    let mut i = 0usize;
    while i < raw.len() {
        if raw[i] == b'\r' {
            if i + 1 >= raw.len() || raw[i + 1] != b'\n' {
                return Err("bare CR in HTTP head");
            }
            lines.push(&raw[start..i]);
            i += 2;
            start = i;
        } else if raw[i] == b'\n' {
            return Err("bare LF in HTTP head");
        } else {
            i += 1;
        }
    }
    lines.push(&raw[start..]);
    Ok(lines)
}

fn parse_http_headers(
    header_lines: &[&[u8]],
    default_until_eof: bool,
) -> Result<ParsedHttpHeaders, &'static str> {
    if header_lines.len() > MAX_HEADER_COUNT {
        return Err("too many HTTP headers");
    }
    let mut headers = Vec::with_capacity(header_lines.len());
    let mut content_lengths = Vec::new();
    let mut transfer_encodings = Vec::new();

    for &line in header_lines {
        if line.is_empty() || matches!(line[0], b' ' | b'\t') {
            return Err("invalid empty or folded HTTP header line");
        }
        let line_str = std::str::from_utf8(line).map_err(|_| "non-UTF-8 HTTP header")?;
        let (name, raw_val) = line_str
            .split_once(':')
            .ok_or("HTTP header missing ':' separator")?;
        if name.is_empty() || !name.bytes().all(is_tchar) {
            return Err("invalid HTTP header name");
        }
        let val = raw_val.trim_matches(|c| c == ' ' || c == '\t');
        if val
            .bytes()
            .any(|b| (b < 0x20 && b != b'\t') || b == 0x7F)
        {
            return Err("invalid control character in HTTP header value");
        }

        if name.eq_ignore_ascii_case("content-length") {
            content_lengths.push(val);
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            transfer_encodings.push(val);
        }
        headers.push((name.to_owned(), val.to_owned()));
    }

    if !content_lengths.is_empty() && !transfer_encodings.is_empty() {
        return Err("conflicting Content-Length and Transfer-Encoding headers");
    }

    let body_mode = if !transfer_encodings.is_empty() {
        if transfer_encodings.len() > 1
            || !transfer_encodings[0].eq_ignore_ascii_case("chunked")
        {
            return Err("unsupported or duplicate Transfer-Encoding");
        }
        BodyMode::Chunked
    } else if !content_lengths.is_empty() {
        if content_lengths.len() > 1 {
            return Err("duplicate Content-Length headers");
        }
        let cl_str = content_lengths[0];
        if cl_str.is_empty() || !cl_str.bytes().all(|b| b.is_ascii_digit()) {
            return Err("invalid Content-Length value");
        }
        let len: u64 = cl_str.parse().map_err(|_| "Content-Length overflow")?;
        BodyMode::ContentLength(len)
    } else if default_until_eof {
        BodyMode::UntilEof
    } else {
        BodyMode::Empty
    };

    Ok(ParsedHttpHeaders { headers, body_mode })
}

fn parse_http_request_head(raw: &[u8]) -> Result<HttpRequestHead, &'static str> {
    let lines = split_crlf_lines(raw)?;
    let (&first_line, header_lines) = lines.split_first().ok_or("empty HTTP request")?;
    let start_str = std::str::from_utf8(first_line).map_err(|_| "non-UTF-8 request line")?;
    let mut parts = start_str.split(' ');
    let method = parts.next().ok_or("missing HTTP method")?;
    let raw_target = parts.next().ok_or("missing HTTP request target")?;
    let version = parts.next().ok_or("missing HTTP version")?;
    if parts.next().is_some() {
        return Err("malformed HTTP request line");
    }
    if method.is_empty() || !method.bytes().all(is_tchar) {
        return Err("invalid HTTP method");
    }
    if raw_target.is_empty() || raw_target.bytes().any(|b| b <= 0x20 || b == 0x7F) {
        return Err("invalid HTTP request target");
    }
    if version != "HTTP/1.1" && version != "HTTP/1.0" {
        return Err("unsupported HTTP version");
    }

    let parsed = parse_http_headers(header_lines, false)?;
    Ok(HttpRequestHead {
        method: method.to_owned(),
        raw_target: raw_target.to_owned(),
        headers: parsed.headers,
        body_mode: parsed.body_mode,
    })
}

fn parse_http_response_head(raw: &[u8]) -> Result<HttpResponseHead, &'static str> {
    let lines = split_crlf_lines(raw)?;
    let (&first_line, header_lines) = lines.split_first().ok_or("empty HTTP response")?;
    let start_str = std::str::from_utf8(first_line).map_err(|_| "non-UTF-8 status line")?;
    let (version, rest) = start_str
        .split_once(' ')
        .ok_or("malformed HTTP status line")?;
    if version != "HTTP/1.1" && version != "HTTP/1.0" {
        return Err("unsupported upstream HTTP version");
    }
    let (status_str, reason) = match rest.split_once(' ') {
        Some((s, r)) => (s, r),
        None => (rest, ""),
    };
    if status_str.len() != 3 || !status_str.bytes().all(|b| b.is_ascii_digit()) {
        return Err("invalid HTTP status code");
    }
    let status: u16 = status_str.parse().map_err(|_| "invalid HTTP status code")?;
    if !(100..=599).contains(&status) {
        return Err("HTTP status code out of range");
    }
    if reason
        .bytes()
        .any(|b| (b < 0x20 && b != b'\t') || b == 0x7F)
    {
        return Err("invalid control character in reason phrase");
    }

    let parsed = parse_http_headers(header_lines, true)?;
    Ok(HttpResponseHead {
        version: version.to_owned(),
        status,
        reason: reason.to_owned(),
        headers: parsed.headers,
        body_mode: parsed.body_mode,
    })
}

fn parse_socks5_host(host: &str) -> Result<TargetHost, ()> {
    if host.is_empty() || host.contains('[') || host.contains(']') {
        return Err(());
    }
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(TargetHost::Ip(ip));
    }
    let norm = normalize_egress_domain(host).map_err(|_| ())?;
    if norm.starts_with("*.") {
        return Err(());
    }
    Ok(TargetHost::Domain(norm))
}

fn parse_authority(authority: &str, default_port: Option<u16>) -> Result<(TargetHost, u16), ()> {
    if authority.is_empty()
        || authority
            .bytes()
            .any(|b| b <= 0x20 || b == 0x7F || matches!(b, b'@' | b'/' | b'?' | b'#' | b'\\'))
    {
        return Err(());
    }

    if let Some(after_open) = authority.strip_prefix('[') {
        let close = after_open.find(']').ok_or(())?;
        let ip_str = &after_open[..close];
        let v6: Ipv6Addr = ip_str.parse().map_err(|_| ())?;
        let rest = &after_open[close + 1..];
        let port = if rest.is_empty() {
            default_port.ok_or(())?
        } else if let Some(port_str) = rest.strip_prefix(':') {
            parse_nonzero_port(port_str)?
        } else {
            return Err(());
        };
        return Ok((TargetHost::Ip(IpAddr::V6(v6)), port));
    }

    if authority.contains('[') || authority.contains(']') {
        return Err(());
    }

    let (host_str, port) = match authority.split_once(':') {
        Some((h, port_str)) => {
            if port_str.contains(':') {
                // Reject unbracketed IPv6 literals.
                return Err(());
            }
            (h, parse_nonzero_port(port_str)?)
        }
        None => (authority, default_port.ok_or(())?),
    };

    if let Ok(v4) = host_str.parse::<Ipv4Addr>() {
        return Ok((TargetHost::Ip(IpAddr::V4(v4)), port));
    }

    let norm = normalize_egress_domain(host_str).map_err(|_| ())?;
    if norm.starts_with("*.") {
        return Err(());
    }
    Ok((TargetHost::Domain(norm), port))
}

fn parse_nonzero_port(port_str: &str) -> Result<u16, ()> {
    if port_str.is_empty() || !port_str.bytes().all(|b| b.is_ascii_digit()) {
        return Err(());
    }
    let port: u16 = port_str.parse().map_err(|_| ())?;
    if port == 0 {
        return Err(());
    }
    Ok(port)
}

fn parse_proxy_http_url(raw_target: &str) -> Result<ParsedProxyHttpUrl, &'static str> {
    if raw_target.contains('#') || raw_target.contains('\\') {
        return Err("invalid characters in proxy target URL");
    }
    let (scheme, after_scheme) = raw_target
        .split_once("://")
        .ok_or("proxy HTTP request target must be an absolute http:// URL")?;
    if !scheme.eq_ignore_ascii_case("http") {
        return Err("unsupported URI scheme in HTTP proxy request");
    }

    let auth_end = after_scheme.find(['/', '?']).unwrap_or(after_scheme.len());
    let authority = &after_scheme[..auth_end];
    let rest = &after_scheme[auth_end..];
    if authority.contains('@') {
        return Err("userinfo@ is not permitted in proxy target URL");
    }

    let (host, port) = parse_authority(authority, Some(80))
        .map_err(|_| "invalid authority in proxy target URL")?;
    let origin_form = if rest.is_empty() {
        "/".to_owned()
    } else if rest.starts_with('?') {
        format!("/{rest}")
    } else {
        rest.to_owned()
    };

    Ok(ParsedProxyHttpUrl {
        host,
        port,
        origin_form,
    })
}

fn parse_redirect_authority(
    after_slashes: &str,
    default_port: u16,
) -> Result<(TargetHost, u16), EgressReject> {
    let auth_end = after_slashes
        .find(['/', '?', '#'])
        .unwrap_or(after_slashes.len());
    let authority = &after_slashes[..auth_end];
    if authority.is_empty() || authority.contains('@') || authority.contains('\\') {
        return Err(EgressReject::Forbidden(
            "invalid authority or userinfo in redirect Location",
        ));
    }
    parse_authority(authority, Some(default_port))
        .map_err(|_| EgressReject::Forbidden("invalid host/port in redirect Location"))
}

fn host_header_matches(headers: &[(String, String)], target_host: &TargetHost, port: u16) -> bool {
    let mut host_values = headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("host"))
        .map(|(_, v)| v.as_str());
    let Some(first) = host_values.next() else {
        return true;
    };
    if host_values.next().is_some() {
        return false;
    }
    let Ok((hdr_host, hdr_port)) = parse_authority(first, Some(port)) else {
        return false;
    };
    &hdr_host == target_host && hdr_port == port
}

fn collect_connection_tokens(headers: &[(String, String)]) -> Vec<String> {
    let mut tokens = Vec::new();
    for (name, val) in headers {
        if name.eq_ignore_ascii_case("connection") {
            for item in val.split(',') {
                let tok = item.trim();
                if !tok.is_empty() {
                    tokens.push(tok.to_ascii_lowercase());
                }
            }
        }
    }
    tokens
}

fn is_hop_by_hop_header(name: &str, connection_tokens: &[String]) -> bool {
    name.eq_ignore_ascii_case("connection")
        || name.eq_ignore_ascii_case("keep-alive")
        || name.eq_ignore_ascii_case("proxy-connection")
        || name.eq_ignore_ascii_case("proxy-authorization")
        || name.eq_ignore_ascii_case("proxy-authenticate")
        || name.eq_ignore_ascii_case("te")
        || name.eq_ignore_ascii_case("trailer")
        || name.eq_ignore_ascii_case("upgrade")
        || connection_tokens
            .iter()
            .any(|tok| tok.eq_ignore_ascii_case(name))
}

fn format_host_header(host: &TargetHost, port: u16) -> String {
    let host_part = match host {
        TargetHost::Ip(IpAddr::V4(v4)) => v4.to_string(),
        TargetHost::Ip(IpAddr::V6(v6)) => format!("[{v6}]"),
        TargetHost::Domain(d) => d.clone(),
    };
    if port == 80 {
        host_part
    } else {
        format!("{host_part}:{port}")
    }
}

fn build_upstream_request_head(
    method: &str,
    origin_form: &str,
    host: &TargetHost,
    port: u16,
    headers: &[(String, String)],
) -> Vec<u8> {
    let conn_tokens = collect_connection_tokens(headers);
    let mut out = format!(
        "{method} {origin_form} HTTP/1.1\r\nHost: {}\r\n",
        format_host_header(host, port)
    )
    .into_bytes();

    for (name, val) in headers {
        if name.eq_ignore_ascii_case("host") || is_hop_by_hop_header(name, &conn_tokens) {
            continue;
        }
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(val.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"Connection: close\r\n\r\n");
    out
}

fn build_client_response_head(resp: &HttpResponseHead, add_close: bool) -> Vec<u8> {
    let conn_tokens = collect_connection_tokens(&resp.headers);
    let mut out = if resp.reason.is_empty() {
        format!("{} {}\r\n", resp.version, resp.status).into_bytes()
    } else {
        format!("{} {} {}\r\n", resp.version, resp.status, resp.reason).into_bytes()
    };

    for (name, val) in &resp.headers {
        if is_hop_by_hop_header(name, &conn_tokens) {
            continue;
        }
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(val.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    if add_close {
        out.extend_from_slice(b"Connection: close\r\n");
    }
    out.extend_from_slice(b"\r\n");
    out
}

async fn forward_body<R, W>(
    reader: &mut PrefixedStream<R>,
    writer: &mut W,
    mode: BodyMode,
) -> io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = [0u8; STREAM_COPY_BUF_BYTES];
    match mode {
        BodyMode::Empty => Ok(()),
        BodyMode::ContentLength(mut remaining) => {
            while remaining > 0 {
                let to_read = usize::try_from(remaining)
                    .unwrap_or(usize::MAX)
                    .min(buf.len());
                let n = reader.read(&mut buf[..to_read]).await?;
                if n == 0 {
                    return Err(io::Error::new(
                        ErrorKind::UnexpectedEof,
                        "truncated Content-Length body",
                    ));
                }
                writer.write_all(&buf[..n]).await?;
                remaining -= n as u64;
            }
            Ok(())
        }
        BodyMode::UntilEof => loop {
            let n = reader.read(&mut buf).await?;
            if n == 0 {
                return Ok(());
            }
            writer.write_all(&buf[..n]).await?;
        },
        BodyMode::Chunked => loop {
            let line = reader.read_line_crlf(MAX_CHUNK_LINE_BYTES).await?;
            let chunk_len = parse_chunk_size_line(&line)?;
            if chunk_len == 0 {
                writer.write_all(b"0\r\n").await?;
                let mut trailer_count = 0usize;
                loop {
                    let trailer = reader.read_line_crlf(MAX_CHUNK_LINE_BYTES).await?;
                    if trailer.is_empty() {
                        writer.write_all(b"\r\n").await?;
                        return Ok(());
                    }
                    trailer_count += 1;
                    if trailer_count > MAX_HEADER_COUNT {
                        return Err(io::Error::new(
                            ErrorKind::InvalidData,
                            "too many chunked trailers",
                        ));
                    }
                    writer.write_all(trailer.as_bytes()).await?;
                    writer.write_all(b"\r\n").await?;
                }
            }

            let hdr = format!("{chunk_len:x}\r\n");
            writer.write_all(hdr.as_bytes()).await?;
            let mut remaining = chunk_len;
            while remaining > 0 {
                let to_read = usize::try_from(remaining)
                    .unwrap_or(usize::MAX)
                    .min(buf.len());
                let n = reader.read(&mut buf[..to_read]).await?;
                if n == 0 {
                    return Err(io::Error::new(
                        ErrorKind::UnexpectedEof,
                        "truncated chunk payload",
                    ));
                }
                writer.write_all(&buf[..n]).await?;
                remaining -= n as u64;
            }
            let mut crlf = [0u8; 2];
            reader.read_exact(&mut crlf).await?;
            if &crlf != b"\r\n" {
                return Err(io::Error::new(
                    ErrorKind::InvalidData,
                    "missing CRLF after chunk payload",
                ));
            }
            writer.write_all(b"\r\n").await?;
        },
    }
}

fn parse_chunk_size_line(line: &str) -> io::Result<u64> {
    let size_part = line.split(';').next().unwrap_or("").trim_end_matches([' ', '\t']);
    if size_part.is_empty() || size_part.len() > 16 || !size_part.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            "invalid chunked encoding size",
        ));
    }
    u64::from_str_radix(size_part, 16)
        .map_err(|_| io::Error::new(ErrorKind::InvalidData, "chunk size overflow"))
}

fn is_supported_forward_method(method: &str) -> bool {
    matches!(
        method,
        "GET" | "HEAD" | "POST" | "PUT" | "DELETE" | "OPTIONS" | "PATCH"
    )
}

fn is_valid_uri_scheme(scheme: &str) -> bool {
    let mut bytes = scheme.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    first.is_ascii_alphabetic()
        && bytes.all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'-' | b'.'))
}

fn is_tchar(b: u8) -> bool {
    b.is_ascii_alphanumeric()
        || matches!(
            b,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

async fn write_and_flush<W: AsyncWrite + Unpin>(writer: &mut W, bytes: &[u8]) -> io::Result<()> {
    writer.write_all(bytes).await?;
    writer.flush().await
}

async fn send_socks5_reply<W: AsyncWrite + Unpin>(writer: &mut W, code: u8) -> io::Result<()> {
    write_and_flush(writer, &[0x05, code, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await
}

async fn write_http_error<W: AsyncWrite + Unpin>(
    writer: &mut W,
    status: u16,
    reason: &str,
    message: &str,
) -> io::Result<()> {
    let resp = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{message}",
        message.len()
    );
    write_and_flush(writer, resp.as_bytes()).await?;
    writer.shutdown().await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    use sandbox_core::EgressRule;
    use tokio::io::DuplexStream;
    use tokio::net::TcpListener;

    struct MockDnsResolver {
        responses: Mutex<VecDeque<io::Result<Vec<SocketAddr>>>>,
        calls: AtomicUsize,
    }

    impl MockDnsResolver {
        fn with_responses(responses: Vec<io::Result<Vec<SocketAddr>>>) -> Arc<Self> {
            Arc::new(Self {
                responses: Mutex::new(VecDeque::from(responses)),
                calls: AtomicUsize::new(0),
            })
        }

        fn call_count(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }

    #[async_trait::async_trait]
    impl HostDnsResolver for MockDnsResolver {
        async fn resolve(&self, _host: &str, _port: u16) -> io::Result<Vec<SocketAddr>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let mut queue = self.responses.lock().expect("mock dns lock");
            queue.pop_front().unwrap_or_else(|| {
                Err(io::Error::new(
                    ErrorKind::NotFound,
                    "no more mock DNS responses",
                ))
            })
        }
    }

    enum MockUpstreamMode {
        HttpCanned(Mutex<VecDeque<Vec<u8>>>),
        Echo,
        FailThenHttp(Mutex<usize>, Mutex<VecDeque<Vec<u8>>>),
    }

    struct MockDialer {
        dialed_addrs: Arc<Mutex<Vec<SocketAddr>>>,
        captured_requests: Arc<Mutex<Vec<Vec<u8>>>>,
        mode: MockUpstreamMode,
    }

    impl MockDialer {
        fn http(responses: Vec<Vec<u8>>) -> Arc<Self> {
            Arc::new(Self {
                dialed_addrs: Arc::new(Mutex::new(Vec::new())),
                captured_requests: Arc::new(Mutex::new(Vec::new())),
                mode: MockUpstreamMode::HttpCanned(Mutex::new(VecDeque::from(responses))),
            })
        }

        fn echo() -> Arc<Self> {
            Arc::new(Self {
                dialed_addrs: Arc::new(Mutex::new(Vec::new())),
                captured_requests: Arc::new(Mutex::new(Vec::new())),
                mode: MockUpstreamMode::Echo,
            })
        }

        fn fail_first_then_http(fail_count: usize, responses: Vec<Vec<u8>>) -> Arc<Self> {
            Arc::new(Self {
                dialed_addrs: Arc::new(Mutex::new(Vec::new())),
                captured_requests: Arc::new(Mutex::new(Vec::new())),
                mode: MockUpstreamMode::FailThenHttp(
                    Mutex::new(fail_count),
                    Mutex::new(VecDeque::from(responses)),
                ),
            })
        }

        fn dialed(&self) -> Vec<SocketAddr> {
            self.dialed_addrs.lock().expect("dialed lock").clone()
        }

        fn captured(&self) -> Vec<Vec<u8>> {
            self.captured_requests.lock().expect("captured lock").clone()
        }
    }

    async fn read_mock_http_request(server_side: &mut DuplexStream) -> Vec<u8> {
        let mut req_buf = Vec::new();
        let mut tmp = [0u8; 4096];
        let head_end = loop {
            match server_side.read(&mut tmp).await {
                Ok(0) | Err(_) => return req_buf,
                Ok(n) => {
                    req_buf.extend_from_slice(&tmp[..n]);
                    if let Some(pos) = req_buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        break pos + 4;
                    }
                }
            }
        };
        let head_text = String::from_utf8_lossy(&req_buf[..head_end]);
        let content_len = head_text
            .lines()
            .find_map(|line| {
                let (name, val) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| val.trim().parse::<usize>().ok())?
            })
            .unwrap_or(0);
        while req_buf.len() < head_end + content_len {
            match server_side.read(&mut tmp).await {
                Ok(0) | Err(_) => break,
                Ok(n) => req_buf.extend_from_slice(&tmp[..n]),
            }
        }
        req_buf
    }

    #[async_trait::async_trait]
    impl UpstreamDialer for MockDialer {
        async fn connect(&self, addr: SocketAddr) -> io::Result<BoxedUpstreamStream> {
            self.dialed_addrs.lock().expect("dialed lock").push(addr);

            match &self.mode {
                MockUpstreamMode::HttpCanned(queue) => {
                    let canned = queue
                        .lock()
                        .expect("canned lock")
                        .pop_front()
                        .unwrap_or_else(|| {
                            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok".to_vec()
                        });
                    let (proxy_side, mut server_side) = tokio::io::duplex(64 * 1024);
                    let captured_ref = Arc::clone(&self.captured_requests);
                    tokio::spawn(async move {
                        let req_buf = read_mock_http_request(&mut server_side).await;
                        captured_ref.lock().expect("cap lock").push(req_buf);
                        let _ = server_side.write_all(&canned).await;
                        let _ = server_side.shutdown().await;
                    });
                    Ok(Box::pin(proxy_side))
                }
                MockUpstreamMode::FailThenHttp(remaining_fails, queue) => {
                    let mut rem = remaining_fails.lock().expect("fails lock");
                    if *rem > 0 {
                        *rem -= 1;
                        return Err(io::Error::new(
                            ErrorKind::ConnectionRefused,
                            "simulated dial failure",
                        ));
                    }
                    drop(rem);
                    let canned = queue
                        .lock()
                        .expect("canned lock")
                        .pop_front()
                        .unwrap_or_else(|| {
                            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok".to_vec()
                        });
                    let (proxy_side, mut server_side) = tokio::io::duplex(64 * 1024);
                    let captured_ref = Arc::clone(&self.captured_requests);
                    tokio::spawn(async move {
                        let req_buf = read_mock_http_request(&mut server_side).await;
                        captured_ref.lock().expect("cap lock").push(req_buf);
                        let _ = server_side.write_all(&canned).await;
                        let _ = server_side.shutdown().await;
                    });
                    Ok(Box::pin(proxy_side))
                }
                MockUpstreamMode::Echo => {
                    let (proxy_side, mut server_side) = tokio::io::duplex(64 * 1024);
                    tokio::spawn(async move {
                        let mut buf = [0u8; 4096];
                        loop {
                            match server_side.read(&mut buf).await {
                                Ok(0) | Err(_) => break,
                                Ok(n) => {
                                    if server_side.write_all(&buf[..n]).await.is_err() {
                                        break;
                                    }
                                    let _ = server_side.flush().await;
                                }
                            }
                        }
                    });
                    Ok(Box::pin(proxy_side))
                }
            }
        }
    }

    async fn run_proxy_once(proxy: &HostEgressProxy, req_bytes: &[u8]) -> Vec<u8> {
        let (mut client, server) = tokio::io::duplex(64 * 1024);
        let proxy_clone = proxy.clone();
        let task = tokio::spawn(async move {
            proxy_clone.handle_stream(server).await;
        });

        client.write_all(req_bytes).await.expect("write client request");
        client.flush().await.expect("flush client request");
        client.shutdown().await.expect("shutdown client write");

        let mut resp = Vec::new();
        client
            .read_to_end(&mut resp)
            .await
            .expect("read proxy response");
        task.await.expect("proxy task join");
        resp
    }

    fn spawn_proxy_duplex(proxy: &HostEgressProxy) -> (DuplexStream, tokio::task::JoinHandle<()>) {
        let (client, server) = tokio::io::duplex(64 * 1024);
        let proxy_clone = proxy.clone();
        let task = tokio::spawn(async move {
            proxy_clone.handle_stream(server).await;
        });
        (client, task)
    }

    #[test]
    fn forbidden_ipv4_covers_all_special_cidrs_and_allows_public_edges() {
        let forbidden = [
            "0.0.0.0",
            "0.255.255.255",
            "10.0.0.1",
            "10.255.255.254",
            "100.64.0.0",
            "100.127.255.255",
            "127.0.0.1",
            "127.255.255.254",
            "169.254.0.1",
            "169.254.169.254",
            "172.16.0.0",
            "172.31.255.255",
            "192.0.0.1",
            "192.0.2.1",
            "192.88.99.1",
            "192.168.1.1",
            "198.18.0.0",
            "198.19.255.255",
            "198.51.100.1",
            "203.0.113.1",
            "224.0.0.1",
            "239.255.255.255",
            "240.0.0.1",
            "255.255.255.255",
        ];
        for s in forbidden {
            let ip: IpAddr = s.parse().unwrap();
            assert!(is_forbidden_ip(ip), "expected {s} to be forbidden");
        }

        let allowed = [
            "1.1.1.1",
            "8.8.8.8",
            "93.184.216.34",
            "100.63.255.255",
            "100.128.0.0",
            "172.15.255.255",
            "172.32.0.0",
            "192.0.1.1",
            "192.88.98.1",
            "198.17.255.255",
            "198.20.0.0",
        ];
        for s in allowed {
            let ip: IpAddr = s.parse().unwrap();
            assert!(!is_forbidden_ip(ip), "expected {s} to be public/allowed");
        }
    }

    #[test]
    fn forbidden_ipv6_covers_all_special_mapped_and_tunneled_cidrs() {
        let forbidden = [
            "::",
            "::1",
            "::8.8.8.8", // ::/96 IPv4-compatible deprecated
            "::127.0.0.1",
            "::ffff:127.0.0.1",
            "::ffff:10.0.0.1",
            "::ffff:169.254.169.254",
            "::ffff:0:127.0.0.1", // ::ffff:0:0:0/96
            "::ffff:0:8.8.8.8",   // ::ffff:0:0:0/96 unconditionally blocked
            "64:ff9b::10.0.0.1",
            "64:ff9b::127.0.0.1",
            "64:ff9b:1::1",
            "2002:7f00:0001::", // 6to4 -> 127.0.0.1
            "2002:0a00:0001::", // 6to4 -> 10.0.0.1
            "2001::1",          // Teredo 2001::/32
            "100::1",           // Discard 100::/64
            "2001:2::1",        // Benchmarking 2001:2::/48
            "2001:db8::1",      // Documentation 2001:db8::/32
            "fc00::1",          // ULA fc00::/7
            "fd00::1",          // ULA fc00::/7
            "fe80::1",          // Link-local fe80::/10
            "febf::1",
            "fec0::1", // Site-local fec0::/10
            "ff02::1", // Multicast ff00::/8
        ];
        for s in forbidden {
            let ip: IpAddr = s.parse().unwrap();
            assert!(is_forbidden_ip(ip), "expected IPv6 {s} to be forbidden");
        }

        let allowed = [
            "::ffff:8.8.8.8",
            "64:ff9b::8.8.8.8",
            "2002:0808:0808::",
            "2001:4860:4860::8888",
            "2606:4700:4700::1111",
        ];
        for s in allowed {
            let ip: IpAddr = s.parse().unwrap();
            assert!(!is_forbidden_ip(ip), "expected IPv6 {s} to be allowed");
        }
    }

    #[tokio::test]
    async fn domain_allow_list_rejects_disallowed_domain_and_raw_ip_before_dns() {
        let dns = MockDnsResolver::with_responses(vec![]);
        let dialer = MockDialer::http(vec![]);
        let policy = NetworkPolicy::DomainAllowList {
            rules: vec![EgressRule {
                domain: "*.example.com".to_owned(),
                port: 80,
            }],
        };
        let proxy = HostEgressProxy::new(policy, dns.clone(), dialer.clone());

        let resp = run_proxy_once(
            &proxy,
            b"GET http://evil-example.com/data HTTP/1.1\r\nHost: evil-example.com\r\n\r\n",
        )
        .await;
        assert!(String::from_utf8_lossy(&resp).starts_with("HTTP/1.1 403 Forbidden"));

        let resp_apex = run_proxy_once(
            &proxy,
            b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n",
        )
        .await;
        assert!(String::from_utf8_lossy(&resp_apex).starts_with("HTTP/1.1 403 Forbidden"));

        let resp_ip = run_proxy_once(
            &proxy,
            b"GET http://93.184.216.34/ HTTP/1.1\r\nHost: 93.184.216.34\r\n\r\n",
        )
        .await;
        assert!(String::from_utf8_lossy(&resp_ip).starts_with("HTTP/1.1 403 Forbidden"));

        let resp_port = run_proxy_once(
            &proxy,
            b"CONNECT api.example.com:443 HTTP/1.1\r\nHost: api.example.com:443\r\n\r\n",
        )
        .await;
        assert!(String::from_utf8_lossy(&resp_port).starts_with("HTTP/1.1 403 Forbidden"));

        assert_eq!(dns.call_count(), 0);
        assert!(dialer.dialed().is_empty());
    }

    #[tokio::test]
    async fn anti_dns_rebinding_blocks_second_lookup_and_mixed_ip_results() {
        let pub_ip: SocketAddr = "93.184.216.34:80".parse().unwrap();
        let loopback_ip: SocketAddr = "127.0.0.1:80".parse().unwrap();
        let mapped_private: SocketAddr = "[::ffff:10.0.0.1]:80".parse().unwrap();

        let dns = MockDnsResolver::with_responses(vec![
            Ok(vec![pub_ip]),
            Ok(vec![loopback_ip]),
            Ok(vec![pub_ip, mapped_private]),
        ]);
        let dialer = MockDialer::http(vec![
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello".to_vec(),
        ]);
        let proxy = HostEgressProxy::new(NetworkPolicy::InternetOnly, dns.clone(), dialer.clone());

        let ok_resp = run_proxy_once(
            &proxy,
            b"GET http://rebind.example.org/step1 HTTP/1.1\r\nHost: rebind.example.org\r\n\r\n",
        )
        .await;
        let ok_text = String::from_utf8_lossy(&ok_resp);
        assert!(ok_text.starts_with("HTTP/1.1 200 OK"), "{ok_text}");
        assert!(ok_text.ends_with("hello"), "{ok_text}");

        let rebind1 = run_proxy_once(
            &proxy,
            b"GET http://rebind.example.org/step2 HTTP/1.1\r\nHost: rebind.example.org\r\n\r\n",
        )
        .await;
        assert!(String::from_utf8_lossy(&rebind1).starts_with("HTTP/1.1 403 Forbidden"));

        let rebind2 = run_proxy_once(
            &proxy,
            b"GET http://rebind.example.org/step3 HTTP/1.1\r\nHost: rebind.example.org\r\n\r\n",
        )
        .await;
        assert!(String::from_utf8_lossy(&rebind2).starts_with("HTTP/1.1 403 Forbidden"));

        assert_eq!(dns.call_count(), 3);
        assert_eq!(dialer.dialed(), vec![pub_ip]);
        let req_sent = String::from_utf8_lossy(&dialer.captured()[0]).into_owned();
        assert!(req_sent.starts_with("GET /step1 HTTP/1.1\r\n"), "{req_sent}");
    }

    #[tokio::test]
    async fn http_redirect_validation_blocks_internal_disallowed_and_rebound_locations() {
        let pub_ip: SocketAddr = "93.184.216.34:80".parse().unwrap();
        let dns = MockDnsResolver::with_responses(vec![
            // req 1 -> api.example.com -> pub_ip (302 to http://127.0.0.1/)
            Ok(vec![pub_ip]),
            // req 2 -> api.example.com -> pub_ip (302 to http://[::ffff:127.0.0.1]/)
            Ok(vec![pub_ip]),
            // req 3 -> api.example.com -> pub_ip (302 to https://evil.example.org/)
            Ok(vec![pub_ip]),
            // req 4 -> api.example.com -> pub_ip (302 to http://cdn.example.com/ -> 169.254.169.254!)
            Ok(vec![pub_ip]),
            Ok(vec!["169.254.169.254:80".parse().unwrap()]),
            // req 5 -> api.example.com -> pub_ip (302 to file:///etc/passwd)
            Ok(vec![pub_ip]),
            // req 6 -> api.example.com -> pub_ip (302 to //127.0.0.1/secret)
            Ok(vec![pub_ip]),
            // req 7 -> api.example.com -> pub_ip (300 Multiple Choices to http://10.0.0.1/)
            Ok(vec![pub_ip]),
            // req 8 -> api.example.com -> pub_ip (302 to legitimate https://cdn.example.com/ok -> pub_ip:443)
            Ok(vec![pub_ip]),
            Ok(vec!["93.184.216.34:443".parse().unwrap()]),
        ]);

        let dialer = MockDialer::http(vec![
            b"HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1/\r\nContent-Length: 0\r\n\r\n"
                .to_vec(),
            b"HTTP/1.1 302 Found\r\nLocation: http://[::ffff:127.0.0.1]/\r\nContent-Length: 0\r\n\r\n"
                .to_vec(),
            b"HTTP/1.1 302 Found\r\nLocation: https://evil.example.org/\r\nContent-Length: 0\r\n\r\n"
                .to_vec(),
            b"HTTP/1.1 302 Found\r\nLocation: http://cdn.example.com/meta\r\nContent-Length: 0\r\n\r\n"
                .to_vec(),
            b"HTTP/1.1 302 Found\r\nLocation: file:///etc/passwd\r\nContent-Length: 0\r\n\r\n"
                .to_vec(),
            b"HTTP/1.1 302 Found\r\nLocation: //127.0.0.1/secret\r\nContent-Length: 0\r\n\r\n"
                .to_vec(),
            b"HTTP/1.1 300 Multiple Choices\r\nLocation: http://10.0.0.1/\r\nContent-Length: 0\r\n\r\n"
                .to_vec(),
            b"HTTP/1.1 302 Found\r\nLocation: https://cdn.example.com/ok\r\nContent-Length: 0\r\n\r\n"
                .to_vec(),
        ]);

        let policy = NetworkPolicy::DomainAllowList {
            rules: vec![
                EgressRule {
                    domain: "*.example.com".to_owned(),
                    port: 80,
                },
                EgressRule {
                    domain: "cdn.example.com".to_owned(),
                    port: 443,
                },
            ],
        };
        let proxy = HostEgressProxy::new(policy, dns.clone(), dialer.clone());
        let req = b"GET http://api.example.com/start HTTP/1.1\r\nHost: api.example.com\r\n\r\n";

        for case in 1..=7 {
            let resp = run_proxy_once(&proxy, req).await;
            let text = String::from_utf8_lossy(&resp);
            assert!(
                text.starts_with("HTTP/1.1 403 Forbidden"),
                "redirect case {case} was not blocked: {text}"
            );
        }

        let ok_redirect = run_proxy_once(&proxy, req).await;
        let ok_text = String::from_utf8_lossy(&ok_redirect);
        assert!(
            ok_text.starts_with("HTTP/1.1 302 Found"),
            "legitimate redirect should pass: {ok_text}"
        );
        assert!(ok_text.contains("Location: https://cdn.example.com/ok"));
    }

    #[tokio::test]
    async fn http_rejects_smuggling_userinfo_and_disallowed_schemes() {
        let dns = MockDnsResolver::with_responses(vec![]);
        let dialer = MockDialer::http(vec![]);
        let proxy = HostEgressProxy::new(NetworkPolicy::InternetOnly, dns.clone(), dialer.clone());

        let bad_requests: &[&[u8]] = &[
            b"POST http://example.com/ HTTP/1.1\r\nHost: example.com\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
            b"GET http://user@example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n",
            b"GET file:///etc/passwd HTTP/1.1\r\nHost: localhost\r\n\r\n",
            b"GET gopher://127.0.0.1:6379/_INFO HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
            b"GET ftp://example.com/file HTTP/1.1\r\nHost: example.com\r\n\r\n",
        ];

        for req in bad_requests {
            let resp = run_proxy_once(&proxy, req).await;
            let text = String::from_utf8_lossy(&resp);
            assert!(
                text.starts_with("HTTP/1.1 400 Bad Request"),
                "expected 400 Bad Request for {:?}, got {text}",
                String::from_utf8_lossy(req)
            );
        }
        assert_eq!(dns.call_count(), 0);
        assert!(dialer.dialed().is_empty());
    }

    #[tokio::test]
    async fn http_connect_flushes_pipelined_bytes_and_relays_bidirectionally() {
        let pub_ip: SocketAddr = "93.184.216.34:443".parse().unwrap();
        let dns = MockDnsResolver::with_responses(vec![Ok(vec![pub_ip])]);
        let dialer = MockDialer::echo();
        let proxy = HostEgressProxy::new(NetworkPolicy::InternetOnly, dns, dialer.clone());

        let (mut client, task) = spawn_proxy_duplex(&proxy);
        client
            .write_all(
                b"CONNECT api.example.com:443 HTTP/1.1\r\nHost: api.example.com:443\r\n\r\npipelined-tls",
            )
            .await
            .unwrap();
        client.flush().await.unwrap();

        let mut head_buf = vec![0u8; 39];
        client.read_exact(&mut head_buf).await.unwrap();
        assert_eq!(&head_buf, b"HTTP/1.1 200 Connection Established\r\n\r\n");

        let mut echoed = vec![0u8; b"pipelined-tls".len()];
        client.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"pipelined-tls");

        client.write_all(b"ping").await.unwrap();
        client.flush().await.unwrap();
        let mut ping_echo = [0u8; 4];
        client.read_exact(&mut ping_echo).await.unwrap();
        assert_eq!(&ping_echo, b"ping");

        client.shutdown().await.unwrap();
        drop(client);
        task.await.unwrap();
        assert_eq!(dialer.dialed(), vec![pub_ip]);
    }

    #[tokio::test]
    async fn socks5_connect_succeeds_and_rejects_bind_udp_and_forbidden_targets() {
        let pub_ip: SocketAddr = "93.184.216.34:443".parse().unwrap();
        let dns = MockDnsResolver::with_responses(vec![Ok(vec![pub_ip])]);
        let dialer = MockDialer::echo();
        let proxy = HostEgressProxy::new(NetworkPolicy::InternetOnly, dns, dialer.clone());

        // 1. CONNECT domain success
        let (mut c1, t1) = spawn_proxy_duplex(&proxy);
        c1.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut method_sel = [0u8; 2];
        c1.read_exact(&mut method_sel).await.unwrap();
        assert_eq!(method_sel, [0x05, 0x00]);

        let domain = b"api.example.com";
        let mut req = vec![0x05, 0x01, 0x00, 0x03, domain.len() as u8];
        req.extend_from_slice(domain);
        req.extend_from_slice(&443u16.to_be_bytes());
        c1.write_all(&req).await.unwrap();

        let mut reply = [0u8; 10];
        c1.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply[..2], &[0x05, 0x00]);

        c1.write_all(b"socks5-hello").await.unwrap();
        let mut echo = [0u8; 12];
        c1.read_exact(&mut echo).await.unwrap();
        assert_eq!(&echo, b"socks5-hello");
        drop(c1);
        t1.await.unwrap();

        // 2. UDP ASSOCIATE (0x03) -> 0x07 Command Not Supported
        let (mut c2, t2) = spawn_proxy_duplex(&proxy);
        c2.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        c2.read_exact(&mut method_sel).await.unwrap();
        c2.write_all(&[0x05, 0x03, 0x00, 0x01, 8, 8, 8, 8, 0, 53])
            .await
            .unwrap();
        c2.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply[1], 0x07);
        drop(c2);
        t2.await.unwrap();

        // 3. BIND (0x02) -> 0x07 Command Not Supported
        let (mut c3, t3) = spawn_proxy_duplex(&proxy);
        c3.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        c3.read_exact(&mut method_sel).await.unwrap();
        c3.write_all(&[0x05, 0x02, 0x00, 0x01, 8, 8, 8, 8, 0, 80])
            .await
            .unwrap();
        c3.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply[1], 0x07);
        drop(c3);
        t3.await.unwrap();

        // 4. Forbidden IPv4 loopback under InternetOnly -> 0x02 Connection Not Allowed
        let (mut c4, t4) = spawn_proxy_duplex(&proxy);
        c4.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        c4.read_exact(&mut method_sel).await.unwrap();
        c4.write_all(&[0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0, 80])
            .await
            .unwrap();
        c4.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply[1], 0x02);
        drop(c4);
        t4.await.unwrap();

        assert_eq!(dialer.dialed(), vec![pub_ip]);
    }

    #[tokio::test]
    async fn isolated_denies_all_and_unrestricted_allows_loopback_tcp_target() {
        let dns = Arc::new(SystemDnsResolver);
        let dialer = Arc::new(TcpUpstreamDialer);

        let isolated = HostEgressProxy::new(NetworkPolicy::Isolated, dns.clone(), dialer.clone());
        let isolated_resp = run_proxy_once(
            &isolated,
            b"GET http://127.0.0.1/ HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
        )
        .await;
        assert!(isolated_resp.is_empty());

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server_task = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 512];
            let _ = sock.read(&mut buf).await.unwrap();
            sock.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\nunrestricted")
                .await
                .unwrap();
            sock.shutdown().await.unwrap();
        });

        let unrestricted = HostEgressProxy::new(NetworkPolicy::Unrestricted, dns, dialer);
        let req = format!(
            "GET http://127.0.0.1:{}/ping HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\n",
            addr.port(),
            addr.port()
        );
        let resp = run_proxy_once(&unrestricted, req.as_bytes()).await;
        let text = String::from_utf8_lossy(&resp);
        assert!(text.starts_with("HTTP/1.1 200 OK"), "{text}");
        assert!(text.ends_with("unrestricted"), "{text}");
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn http_post_strips_proxy_headers_forwards_body_and_retries_validated_ips() {
        let ip1: SocketAddr = "93.184.216.34:80".parse().unwrap();
        let ip2: SocketAddr = "93.184.216.35:80".parse().unwrap();
        let dns = MockDnsResolver::with_responses(vec![Ok(vec![ip1, ip2]), Ok(vec![ip1])]);
        let dialer = MockDialer::fail_first_then_http(
            1,
            vec![
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n"
                    .to_vec(),
                b"HTTP/1.1 302 Found\r\nLocation: /login?next=1\r\nContent-Length: 0\r\n\r\n"
                    .to_vec(),
            ],
        );
        let policy = NetworkPolicy::DomainAllowList {
            rules: vec![EgressRule {
                domain: "api.example.com".to_owned(),
                port: 80,
            }],
        };
        let proxy = HostEgressProxy::new(policy, dns.clone(), dialer.clone());

        let post_req = concat!(
            "POST http://api.example.com/submit?v=1 HTTP/1.1\r\n",
            "Host: api.example.com\r\n",
            "Proxy-Authorization: Basic secret\r\n",
            "Proxy-Connection: keep-alive\r\n",
            "Content-Length: 7\r\n\r\n",
            "payload"
        );
        let resp1 = run_proxy_once(&proxy, post_req.as_bytes()).await;
        let text1 = String::from_utf8_lossy(&resp1);
        assert!(text1.starts_with("HTTP/1.1 200 OK"), "{text1}");
        assert!(text1.contains("5\r\nhello\r\n0\r\n\r\n"), "{text1}");

        let sent = String::from_utf8_lossy(&dialer.captured()[0]).into_owned();
        assert!(sent.starts_with("POST /submit?v=1 HTTP/1.1\r\n"), "{sent}");
        assert!(!sent.contains("Proxy-Authorization"), "{sent}");
        assert!(!sent.contains("Proxy-Connection"), "{sent}");
        assert!(sent.ends_with("payload"), "{sent}");

        let rel_redirect_req =
            b"GET http://api.example.com/home HTTP/1.1\r\nHost: api.example.com\r\n\r\n";
        let resp2 = run_proxy_once(&proxy, rel_redirect_req).await;
        let text2 = String::from_utf8_lossy(&resp2);
        assert!(text2.starts_with("HTTP/1.1 302 Found"), "{text2}");
        assert!(text2.contains("Location: /login?next=1"), "{text2}");

        assert_eq!(dns.call_count(), 2);
        assert_eq!(dialer.dialed(), vec![ip1, ip2, ip1]);
    }

    #[tokio::test]
    async fn idle_handshake_and_idle_tunnel_streams_expire_within_configured_timeouts() {
        let dns = MockDnsResolver::with_responses(vec![Ok(vec![SocketAddr::from((
            [93, 184, 216, 34],
            443,
        ))])]);
        let (mut peer_a, upstream_b) = tokio::io::duplex(4096);
        let upstream_slot = Arc::new(std::sync::Mutex::new(Some(upstream_b)));
        struct HoldOpenDialer(Arc<std::sync::Mutex<Option<tokio::io::DuplexStream>>>);
        #[async_trait::async_trait]
        impl UpstreamDialer for HoldOpenDialer {
            async fn connect(&self, _addr: SocketAddr) -> io::Result<BoxedUpstreamStream> {
                let s = self
                    .0
                    .lock()
                    .unwrap()
                    .take()
                    .ok_or_else(|| io::Error::new(ErrorKind::Other, "already taken"))?;
                Ok(Box::pin(s))
            }
        }

        let proxy = HostEgressProxy::with_timeouts(
            NetworkPolicy::InternetOnly,
            dns,
            Arc::new(HoldOpenDialer(upstream_slot)),
            Duration::from_millis(60),
            Duration::from_millis(80),
        );

        // 1. Silent stream sending zero bytes must be reaped by handshake_timeout.
        let (mut idle_client, proxy_side) = tokio::io::duplex(1024);
        let p1 = proxy.clone();
        let h1 = tokio::spawn(async move {
            p1.handle_stream(proxy_side).await;
        });
        tokio::time::timeout(Duration::from_secs(1), h1)
            .await
            .expect("silent stream must time out promptly")
            .unwrap();
        let mut probe = [0u8; 4];
        assert_eq!(idle_client.read(&mut probe).await.unwrap(), 0);

        // 2. Established CONNECT tunnel that goes idle must be reaped by idle_timeout.
        let (mut tunnel_client, proxy_side2) = tokio::io::duplex(4096);
        let p2 = proxy.clone();
        let h2 = tokio::spawn(async move {
            p2.handle_stream(proxy_side2).await;
        });
        tunnel_client
            .write_all(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
            .await
            .unwrap();
        let mut resp_buf = [0u8; 64];
        let n = tunnel_client.read(&mut resp_buf).await.unwrap();
        assert!(String::from_utf8_lossy(&resp_buf[..n]).starts_with("HTTP/1.1 200"));

        // Keep peer_a open without sending anything; proxy must terminate after idle_timeout.
        tokio::time::timeout(Duration::from_secs(1), h2)
            .await
            .expect("idle established tunnel must time out promptly")
            .unwrap();
        assert_eq!(peer_a.read(&mut probe).await.unwrap(), 0);
    }
}
