//! HTTP/1.1 Docker Engine API compatibility router, hijack dispatcher, and host listeners.

use std::io;
#[cfg(test)]
use std::net::SocketAddr;
#[cfg(unix)]
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use std::time::Duration;

use sandbox_core::{SandboxError, SandboxId};
use sandbox_runtime::{SandboxTunnelPort, TunnelStream};
use serde_json::Value;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
#[cfg(test)]
use tokio::net::TcpListener;
#[cfg(windows)]
use tokio::sync::watch;
#[cfg(any(unix, windows))]
use tokio::sync::Semaphore;
use tokio::task::JoinHandle;

use crate::hijack::relay_upgraded;
use crate::http1::{
    forward_body, read_body_bytes, read_request_head, read_response_head, write_json_error,
    write_request_head, write_response_head, BodyMode, HttpError, HttpRequestHead,
    HttpResponseHead, PrefixedReader, MAX_BUFFERED_BODY_BYTES,
};
use crate::policy::{
    sanitize_container_create, sanitize_exec_create, sanitize_network_connect,
    sanitize_network_create, sanitize_volume_create, validate_image_build_query,
    validate_image_create_query, DockerCompatPolicy, PolicyRejection, ReaperSocketPolicy,
};
use crate::ports::PortForwardRegistry;
use crate::rewrite::{rewrite_container_inspect_json, rewrite_containers_list_json};

#[cfg(any(unix, windows))]
const MAX_CONCURRENT_DOCKER_CONNECTIONS: usize = 128;
#[cfg(any(unix, windows))]
const DOCKER_ACCEPT_RETRY_BACKOFF: Duration = Duration::from_millis(25);

/// Docker Engine API compatibility proxy forwarding over [`SandboxTunnelPort`].
pub struct DockerCompatServer {
    tunnel_port: Arc<dyn SandboxTunnelPort>,
    sandbox_id: SandboxId,
    reaper_socket_enabled: AtomicBool,
    container_proxy_http_url: Option<String>,
    registry: Arc<PortForwardRegistry>,
}

/// Active loopback TCP listener handle for unit tests (`#[cfg(test)]` only).
#[cfg(test)]
pub struct HttpServerHandle {
    local_addr: SocketAddr,
    task: Option<JoinHandle<()>>,
}

#[cfg(test)]
impl HttpServerHandle {
    /// Returns the actual bound loopback socket address.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Aborts the accept loop and waits for the listening socket to close.
    pub async fn shutdown(mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
            let _ = task.await;
        }
    }
}

#[cfg(test)]
impl Drop for HttpServerHandle {
    fn drop(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

/// Active owner-only Windows Named Pipe listener handle for [`DockerCompatServer::bind_named_pipe_with_factory`].
#[cfg(windows)]
pub struct NamedPipeServerHandle {
    pipe_uri: String,
    pipe_path: String,
    shutdown_tx: watch::Sender<bool>,
    task: Option<JoinHandle<()>>,
}

#[cfg(windows)]
impl NamedPipeServerHandle {
    /// Returns the `DOCKER_HOST`-compatible Named Pipe URI (`npipe:////./pipe/<name>`).
    pub fn uri(&self) -> &str {
        &self.pipe_uri
    }

    /// Returns the Win32 Named Pipe path (`\\.\pipe\<name>`).
    pub fn pipe_path(&self) -> &str {
        &self.pipe_path
    }

    /// Signals the accept loop to stop and waits for the listening pipe instance to close.
    pub async fn shutdown(mut self) {
        let _ = self.shutdown_tx.send(true);
        if let Some(task) = self.task.take() {
            let _ = task.await;
        }
    }
}

#[cfg(windows)]
impl Drop for NamedPipeServerHandle {
    fn drop(&mut self) {
        let _ = self.shutdown_tx.send(true);
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

/// Active owner-only Unix socket listener handle for [`DockerCompatServer::bind_unix_owner_only`].
#[cfg(unix)]
pub struct UnixServerHandle {
    socket_path: PathBuf,
    task: Option<JoinHandle<()>>,
}

#[cfg(unix)]
impl UnixServerHandle {
    /// Returns the bound Unix socket path.
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    /// Aborts the accept loop, waits for the listener to close, and removes the socket file.
    pub async fn shutdown(mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
            let _ = task.await;
        }
        let _ = std::fs::remove_file(&self.socket_path);
    }
}

#[cfg(unix)]
impl Drop for UnixServerHandle {
    fn drop(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
        }
        let _ = std::fs::remove_file(&self.socket_path);
    }
}

enum StreamNext {
    Continue,
    Close,
    Hijacked {
        upstream_stream: TunnelStream,
        upstream_pre_buf: Vec<u8>,
    },
}

enum DockerRoute<'a> {
    ForbiddenLibpod,
    ForbiddenRoute(&'static str),
    ContainerCreate,
    VolumeCreate,
    ContainerExecCreate,
    NetworkCreate,
    NetworkConnect {
        id: String,
    },
    ImageBuild,
    ImageCreate,
    ContainerStart {
        version_prefix: Option<&'a str>,
        raw_id: &'a str,
        id: String,
    },
    ContainerRestart {
        version_prefix: Option<&'a str>,
        raw_id: &'a str,
        id: String,
    },
    ContainerStop {
        id: String,
    },
    ContainerKill {
        id: String,
    },
    ContainerDelete {
        id: String,
    },
    ContainerInspect {
        id: String,
    },
    ContainerList,
    ExecOrAttachHijack,
    PassThrough,
}

impl DockerCompatServer {
    /// Creates a new Docker compatibility server backed by `tunnel_port` for `sandbox_id`.
    pub fn new(
        tunnel_port: Arc<dyn SandboxTunnelPort>,
        sandbox_id: SandboxId,
        policy: DockerCompatPolicy,
    ) -> Self {
        Self {
            tunnel_port,
            sandbox_id,
            reaper_socket_enabled: AtomicBool::new(
                policy.reaper_socket == ReaperSocketPolicy::MapGuestPodmanSocket,
            ),
            container_proxy_http_url: policy.container_proxy_http_url,
            registry: Arc::new(PortForwardRegistry::new()),
        }
    }

    /// Returns the host TCP port forward registry managed by this server.
    pub fn registry(&self) -> &Arc<PortForwardRegistry> {
        &self.registry
    }

    /// Returns the active Docker compatibility security policy.
    pub fn policy(&self) -> DockerCompatPolicy {
        DockerCompatPolicy {
            reaper_socket: if self.reaper_socket_enabled.load(Ordering::Acquire) {
                ReaperSocketPolicy::MapGuestPodmanSocket
            } else {
                ReaperSocketPolicy::Deny
            },
            container_proxy_http_url: self.container_proxy_http_url.clone(),
        }
    }

    /// Updates the reaper socket mapping policy dynamically without disrupting active listeners or port forwards.
    pub fn set_reaper_socket_policy(&self, policy: ReaperSocketPolicy) {
        self.reaper_socket_enabled.store(
            policy == ReaperSocketPolicy::MapGuestPodmanSocket,
            Ordering::Release,
        );
    }

    /// Returns the sandbox identifier bound to this server.
    pub fn sandbox_id(&self) -> &SandboxId {
        &self.sandbox_id
    }

    /// Serves HTTP/1.1 requests (including keep-alive and `101` upgraded streams) over `stream`.
    pub async fn serve_stream<S>(&self, stream: S) -> io::Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let mut client_reader = PrefixedReader::new(stream);
        loop {
            let req = match read_request_head(&mut client_reader).await {
                Ok(Some(req)) => req,
                Ok(None) | Err(HttpError::UnexpectedEof) => return Ok(()),
                Err(HttpError::HeadersTooLarge { limit }) => {
                    let _ = write_json_error(
                        &mut client_reader,
                        431,
                        "Request Header Fields Too Large",
                        &format!("HTTP request headers exceed {limit} bytes"),
                        true,
                    )
                    .await;
                    return Ok(());
                }
                Err(HttpError::MalformedHead(msg)) => {
                    let _ =
                        write_json_error(&mut client_reader, 400, "Bad Request", &msg, true).await;
                    return Ok(());
                }
                Err(HttpError::Io(err)) => return Err(err),
                Err(err) => {
                    let _ = write_json_error(
                        &mut client_reader,
                        400,
                        "Bad Request",
                        &err.to_string(),
                        true,
                    )
                    .await;
                    return Ok(());
                }
            };

            match self.dispatch_request(&mut client_reader, req).await? {
                StreamNext::Continue => continue,
                StreamNext::Close => return Ok(()),
                StreamNext::Hijacked {
                    upstream_stream,
                    upstream_pre_buf,
                } => {
                    let (client_stream, client_pre_buf) = client_reader.into_parts();
                    relay_upgraded(
                        client_stream,
                        &client_pre_buf,
                        upstream_stream,
                        &upstream_pre_buf,
                    )
                    .await?;
                    return Ok(());
                }
            }
        }
    }

    /// Binds an owner-only Unix domain socket listener (`0700` parent dir, `0600` socket) and
    /// spawns the accept loop.
    #[cfg(unix)]
    pub async fn bind_unix_owner_only(
        self: &Arc<Self>,
        socket_path: &Path,
    ) -> Result<UnixServerHandle, SandboxError> {
        let parent = socket_path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .ok_or_else(|| {
                SandboxError::InvalidSpec(format!(
                    "Unix socket path '{}' must have a parent directory",
                    socket_path.display()
                ))
            })?;
        if socket_path.file_name().is_none() {
            return Err(SandboxError::InvalidSpec(format!(
                "Unix socket path '{}' must end with a socket filename",
                socket_path.display()
            )));
        }

        unix_acl::ensure_owner_only_dir(parent)?;
        unix_acl::remove_stale_socket_if_safe(socket_path)?;

        let listener = tokio::net::UnixListener::bind(socket_path).map_err(|err| {
            SandboxError::Transport(format!(
                "failed to bind Unix socket '{}': {err}",
                socket_path.display()
            ))
        })?;

        use std::os::unix::fs::PermissionsExt;
        if let Err(err) =
            std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o600))
        {
            drop(listener);
            let _ = std::fs::remove_file(socket_path);
            return Err(SandboxError::Transport(format!(
                "failed to enforce 0600 permissions on Unix socket '{}': {err}",
                socket_path.display()
            )));
        }

        let server = Arc::clone(self);
        let conn_sem = Arc::new(Semaphore::new(MAX_CONCURRENT_DOCKER_CONNECTIONS));
        let task = tokio::spawn(async move {
            loop {
                let Ok(permit) = Arc::clone(&conn_sem).acquire_owned().await else {
                    break;
                };
                match listener.accept().await {
                    Ok((stream, _)) => {
                        let srv = Arc::clone(&server);
                        tokio::spawn(async move {
                            let _permit = permit;
                            let _ = srv.serve_stream(stream).await;
                        });
                    }
                    Err(err) => {
                        drop(permit);
                        if matches!(
                            err.kind(),
                            io::ErrorKind::ConnectionAborted
                                | io::ErrorKind::ConnectionReset
                                | io::ErrorKind::Interrupted
                        ) {
                            continue;
                        }
                        tokio::time::sleep(DOCKER_ACCEPT_RETRY_BACKOFF).await;
                    }
                }
            }
        });

        Ok(UnixServerHandle {
            socket_path: socket_path.to_path_buf(),
            task: Some(task),
        })
    }

    /// Binds an owner-only Windows Named Pipe listener using the caller-provided factory closure
    /// (which enforces `FILE_FLAG_FIRST_PIPE_INSTANCE`, `PIPE_REJECT_REMOTE_CLIENTS`, and an
    /// owner-only Win32 DACL) and spawns the multi-instance accept loop.
    #[cfg(windows)]
    pub fn bind_named_pipe_with_factory<F>(
        self: &Arc<Self>,
        pipe_name: &str,
        mut create_pipe: F,
    ) -> Result<NamedPipeServerHandle, SandboxError>
    where
        F: FnMut(
                &str,
                bool,
            )
                -> Result<tokio::net::windows::named_pipe::NamedPipeServer, SandboxError>
            + Send
            + 'static,
    {
        if pipe_name.is_empty()
            || pipe_name.contains('\\')
            || pipe_name.contains('/')
            || pipe_name.contains('\0')
            || pipe_name.contains("..")
        {
            return Err(SandboxError::InvalidSpec(format!(
                "invalid Docker Named Pipe leaf name '{pipe_name}'"
            )));
        }

        let mut server_pipe = create_pipe(pipe_name, true)?;
        let pipe_uri = format!("npipe:////./pipe/{pipe_name}");
        let pipe_path = format!(r"\\.\pipe\{pipe_name}");
        let name_owned = pipe_name.to_owned();
        let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
        let compat = Arc::clone(self);
        let conn_sem = Arc::new(Semaphore::new(MAX_CONCURRENT_DOCKER_CONNECTIONS));

        let task = tokio::spawn(async move {
            loop {
                let permit = tokio::select! {
                    biased;
                    _ = shutdown_rx.wait_for(|done| *done) => break,
                    res = Arc::clone(&conn_sem).acquire_owned() => match res {
                        Ok(p) => p,
                        Err(_) => break,
                    },
                };
                let accepted = tokio::select! {
                    biased;
                    _ = shutdown_rx.wait_for(|done| *done) => break,
                    res = server_pipe.connect() => res,
                };
                match accepted {
                    Ok(()) => match create_pipe(&name_owned, false) {
                        Ok(next_pipe) => {
                            let connected = std::mem::replace(&mut server_pipe, next_pipe);
                            let srv = Arc::clone(&compat);
                            tokio::spawn(async move {
                                let _permit = permit;
                                let _ = srv.serve_stream(connected).await;
                            });
                        }
                        Err(_) => {
                            let connected = server_pipe;
                            let srv = Arc::clone(&compat);
                            tokio::spawn(async move {
                                let _permit = permit;
                                let _ = srv.serve_stream(connected).await;
                            });
                            let Some(next_pipe) = reopen_docker_pipe_with_backoff(
                                &name_owned,
                                &mut create_pipe,
                                &mut shutdown_rx,
                            )
                            .await
                            else {
                                break;
                            };
                            server_pipe = next_pipe;
                        }
                    },
                    Err(_) => {
                        drop(permit);
                        match create_pipe(&name_owned, false) {
                            Ok(next_pipe) => {
                                server_pipe = next_pipe;
                            }
                            Err(_) => {
                                drop(server_pipe);
                                let Some(next_pipe) = reopen_docker_pipe_with_backoff(
                                    &name_owned,
                                    &mut create_pipe,
                                    &mut shutdown_rx,
                                )
                                .await
                                else {
                                    break;
                                };
                                server_pipe = next_pipe;
                            }
                        }
                    }
                }
            }
        });

        Ok(NamedPipeServerHandle {
            pipe_uri,
            pipe_path,
            shutdown_tx,
            task: Some(task),
        })
    }

    /// Binds a loopback-only HTTP/1.1 TCP listener for in-crate router unit tests (`#[cfg(test)]`).
    #[cfg(test)]
    pub async fn bind_loopback_http(
        self: &Arc<Self>,
        addr: SocketAddr,
    ) -> Result<HttpServerHandle, SandboxError> {
        if !addr.ip().is_loopback() {
            return Err(SandboxError::PolicyViolation(format!(
                "refusing non-loopback Docker HTTP bind address '{addr}'"
            )));
        }

        let listener = TcpListener::bind(addr).await.map_err(|err| {
            SandboxError::Transport(format!(
                "failed to bind Docker HTTP listener on '{addr}': {err}"
            ))
        })?;
        let local_addr = listener.local_addr().map_err(|err| {
            SandboxError::Transport(format!("failed to read bound listener address: {err}"))
        })?;

        let server = Arc::clone(self);
        let task = tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, _)) => {
                        let _ = stream.set_nodelay(true);
                        let srv = Arc::clone(&server);
                        tokio::spawn(async move {
                            let _ = srv.serve_stream(stream).await;
                        });
                    }
                    Err(err) => {
                        if matches!(
                            err.kind(),
                            io::ErrorKind::ConnectionAborted
                                | io::ErrorKind::ConnectionReset
                                | io::ErrorKind::Interrupted
                        ) {
                            continue;
                        }
                        break;
                    }
                }
            }
        });

        Ok(HttpServerHandle {
            local_addr,
            task: Some(task),
        })
    }

    async fn dispatch_request<S>(
        &self,
        client: &mut PrefixedReader<S>,
        mut req: HttpRequestHead,
    ) -> io::Result<StreamNext>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let canonical_path = match canonicalize_docker_path(&req.path) {
            Ok(path) => path,
            Err(reason) => {
                write_json_error(client, 400, "Bad Request", reason, true)
                    .await
                    .map_err(http_to_io)?;
                return Ok(StreamNext::Close);
            }
        };
        req.path = canonical_path;
        req.raw_target = match &req.query {
            Some(q) => format!("{}?{q}", req.path),
            None => req.path.clone(),
        };

        let route = match parse_docker_route(&req.method, &req.path) {
            DockerRoute::ForbiddenLibpod => {
                // Close if `req` carries an unread body or upgrade intent so keep-alive framing never desyncs.
                let close = should_close_rejected_request(&req, false);
                write_json_error(
                    client,
                    403,
                    "Forbidden",
                    "Podman native /libpod API is disabled on the Docker compatibility endpoint",
                    close,
                )
                .await
                .map_err(http_to_io)?;
                return Ok(if close {
                    StreamNext::Close
                } else {
                    StreamNext::Continue
                });
            }
            DockerRoute::ForbiddenRoute(reason) => {
                let close = should_close_rejected_request(&req, false);
                write_json_error(client, 403, "Forbidden", reason, close)
                    .await
                    .map_err(http_to_io)?;
                return Ok(if close {
                    StreamNext::Close
                } else {
                    StreamNext::Continue
                });
            }
            DockerRoute::ContainerCreate => {
                let (ver_prefix, _) = strip_api_version(&req.path);
                req.path = match ver_prefix {
                    Some(vp) => format!("{vp}/containers/create"),
                    None => "/containers/create".to_owned(),
                };
                req.raw_target = match &req.query {
                    Some(q) => format!("{}?{q}", req.path),
                    None => req.path.clone(),
                };
                return self.handle_container_create(client, req).await;
            }
            DockerRoute::VolumeCreate => {
                return self
                    .handle_sanitized_json_post(
                        client,
                        req,
                        "volume create",
                        |raw, _| sanitize_volume_create(raw).map(|b| (b, ())),
                        |_, _, _, ()| {},
                    )
                    .await;
            }
            DockerRoute::ContainerExecCreate => {
                return self
                    .handle_sanitized_json_post(
                        client,
                        req,
                        "exec create",
                        |raw, policy| sanitize_exec_create(raw, policy).map(|b| (b, ())),
                        |_, _, _, ()| {},
                    )
                    .await;
            }
            DockerRoute::NetworkCreate => {
                return self
                    .handle_sanitized_json_post(
                        client,
                        req,
                        "network create",
                        |raw, _| sanitize_network_create(raw).map(|b| (b, ())),
                        |_, _, _, ()| {},
                    )
                    .await;
            }
            DockerRoute::NetworkConnect { id } => {
                return self
                    .handle_sanitized_json_post(
                        client,
                        req,
                        "network connect",
                        move |raw, _| sanitize_network_connect(&id, raw).map(|b| (b, ())),
                        |_, _, _, ()| {},
                    )
                    .await;
            }
            DockerRoute::ImageBuild => {
                let params = decode_all_query_params(req.query.as_deref());
                if let Err(rejection) = validate_image_build_query(&params) {
                    let close = should_close_rejected_request(&req, false);
                    write_json_error(client, 400, "Bad Request", rejection.reason(), close)
                        .await
                        .map_err(http_to_io)?;
                    return Ok(if close {
                        StreamNext::Close
                    } else {
                        StreamNext::Continue
                    });
                }
                RouteDispatch::Pass
            }
            DockerRoute::ImageCreate => {
                let params = decode_all_query_params(req.query.as_deref());
                if let Err(rejection) = validate_image_create_query(&params) {
                    let close = should_close_rejected_request(&req, false);
                    write_json_error(client, 400, "Bad Request", rejection.reason(), close)
                        .await
                        .map_err(http_to_io)?;
                    return Ok(if close {
                        StreamNext::Close
                    } else {
                        StreamNext::Continue
                    });
                }
                RouteDispatch::Pass
            }
            DockerRoute::ContainerStart {
                version_prefix,
                raw_id,
                id,
            } => RouteDispatch::Start {
                version_prefix: version_prefix.map(str::to_owned),
                raw_id: raw_id.to_owned(),
                id,
            },
            DockerRoute::ContainerRestart {
                version_prefix,
                raw_id,
                id,
            } => RouteDispatch::Restart {
                version_prefix: version_prefix.map(str::to_owned),
                raw_id: raw_id.to_owned(),
                id,
            },
            DockerRoute::ContainerStop { id } | DockerRoute::ContainerKill { id } => {
                RouteDispatch::StopOrKill { id }
            }
            DockerRoute::ContainerDelete { id } => RouteDispatch::Delete { id },
            DockerRoute::ContainerInspect { id } => RouteDispatch::Inspect { id },
            DockerRoute::ContainerList => RouteDispatch::List,
            DockerRoute::ExecOrAttachHijack | DockerRoute::PassThrough => RouteDispatch::Pass,
        };

        enum RouteDispatch {
            Start {
                version_prefix: Option<String>,
                raw_id: String,
                id: String,
            },
            Restart {
                version_prefix: Option<String>,
                raw_id: String,
                id: String,
            },
            StopOrKill {
                id: String,
            },
            Delete {
                id: String,
            },
            Inspect {
                id: String,
            },
            List,
            Pass,
        }

        match route {
            RouteDispatch::Start {
                version_prefix,
                raw_id,
                id,
            }
            | RouteDispatch::Restart {
                version_prefix,
                raw_id,
                id,
            } => {
                self.handle_start_or_restart(
                    client,
                    &req,
                    version_prefix.as_deref(),
                    &raw_id,
                    &id,
                )
                .await
            }
            RouteDispatch::StopOrKill { id } => {
                self.handle_stop_kill_or_delete(client, &req, &id, false)
                    .await
            }
            RouteDispatch::Delete { id } => {
                self.handle_stop_kill_or_delete(client, &req, &id, true)
                    .await
            }
            RouteDispatch::Inspect { id } => self.handle_container_inspect(client, &req, &id).await,
            RouteDispatch::List => self.handle_containers_list(client, &req).await,
            RouteDispatch::Pass => self.handle_passthrough_or_hijack(client, &req).await,
        }
    }

    async fn handle_container_create<S>(
        &self,
        client: &mut PrefixedReader<S>,
        req: HttpRequestHead,
    ) -> io::Result<StreamNext>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let registry = Arc::clone(&self.registry);
        self.handle_sanitized_json_post(
            client,
            req,
            "container create",
            |raw, policy| {
                let plan = sanitize_container_create(raw, policy)?;
                Ok((plan.rewritten_body, plan.requested_ports))
            },
            move |req_head, resp_head, resp_body, requested_ports| {
                if (200..300).contains(&resp_head.status) {
                    if let Ok(parsed) = serde_json::from_slice::<Value>(resp_body) {
                        if let Some(container_id) = parsed
                            .get("Id")
                            .and_then(Value::as_str)
                            .map(str::trim)
                            .filter(|s| !s.is_empty())
                        {
                            let name = extract_query_param(req_head.query.as_deref(), "name");
                            registry.record_create(container_id, name.as_deref(), requested_ports);
                        }
                    }
                }
            },
        )
        .await
    }

    async fn handle_sanitized_json_post<S, M, F, C>(
        &self,
        client: &mut PrefixedReader<S>,
        req: HttpRequestHead,
        label: &str,
        sanitize: F,
        on_response: C,
    ) -> io::Result<StreamNext>
    where
        S: AsyncRead + AsyncWrite + Unpin,
        F: FnOnce(&[u8], &DockerCompatPolicy) -> Result<(Vec<u8>, M), PolicyRejection>,
        C: FnOnce(&HttpRequestHead, &HttpResponseHead, &[u8], M),
    {
        let Some(mut up_req) = prepare_expect_header(client, &req).await? else {
            return Ok(StreamNext::Close);
        };

        let raw_body = match read_body_bytes(client, req.body_mode(), MAX_BUFFERED_BODY_BYTES).await
        {
            Ok(body) => body,
            Err(HttpError::BodyTooLarge { limit }) => {
                let _ = write_json_error(
                    client,
                    413,
                    "Payload Too Large",
                    &format!("{label} body exceeds {limit} bytes"),
                    true,
                )
                .await;
                return Ok(StreamNext::Close);
            }
            Err(HttpError::Io(err)) => return Err(err),
            Err(err) => {
                let _ = write_json_error(client, 400, "Bad Request", &err.to_string(), true).await;
                return Ok(StreamNext::Close);
            }
        };

        let policy = self.policy();
        let (rewritten, meta) = match sanitize(&raw_body, &policy) {
            Ok(pair) => pair,
            Err(rejection) => {
                let close = should_close_rejected_request(&req, true);
                write_json_error(client, 400, "Bad Request", rejection.reason(), close)
                    .await
                    .map_err(http_to_io)?;
                return Ok(if close {
                    StreamNext::Close
                } else {
                    StreamNext::Continue
                });
            }
        };

        set_buffered_body_headers(&mut up_req.headers, rewritten.len(), true);

        let mut upstream = match self
            .tunnel_port
            .open_podman_unix_stream(&self.sandbox_id)
            .await
        {
            Ok(stream) => stream,
            Err(err) => {
                let close = should_close_rejected_request(&req, true);
                write_json_error(client, 502, "Bad Gateway", &err.to_string(), close)
                    .await
                    .map_err(http_to_io)?;
                return Ok(if close {
                    StreamNext::Close
                } else {
                    StreamNext::Continue
                });
            }
        };

        if let Err(err) = write_request_and_bytes(&mut upstream, &up_req, &rewritten).await {
            let close = should_close_rejected_request(&req, true);
            write_json_error(client, 502, "Bad Gateway", &err.to_string(), close)
                .await
                .map_err(http_to_io)?;
            return Ok(if close {
                StreamNext::Close
            } else {
                StreamNext::Continue
            });
        }

        let mut up_reader = PrefixedReader::new(upstream);
        let (mut resp_head, resp_body) =
            match read_buffered_upstream_response(&mut up_reader, &req.method).await {
                Ok(res) => res,
                Err(err) => {
                    let close = req.wants_close();
                    write_json_error(client, 502, "Bad Gateway", &err.to_string(), close)
                        .await
                        .map_err(http_to_io)?;
                    return Ok(if close {
                        StreamNext::Close
                    } else {
                        StreamNext::Continue
                    });
                }
            };

        on_response(&req, &resp_head, &resp_body, meta);
        write_buffered_response(client, &req, &mut resp_head, &resp_body).await
    }

    async fn handle_start_or_restart<S>(
        &self,
        client: &mut PrefixedReader<S>,
        req: &HttpRequestHead,
        version_prefix: Option<&str>,
        raw_id: &str,
        id: &str,
    ) -> io::Result<StreamNext>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let mut up_reader = match self.forward_request_to_upstream(client, req).await {
            Ok(reader) => reader,
            Err(err_next) => return err_next,
        };

        let (mut resp_head, resp_body) =
            match read_buffered_upstream_response(&mut up_reader, &req.method).await {
                Ok(res) => res,
                Err(err) => {
                    let close = req.wants_close();
                    write_json_error(client, 502, "Bad Gateway", &err.to_string(), close)
                        .await
                        .map_err(http_to_io)?;
                    return Ok(if close {
                        StreamNext::Close
                    } else {
                        StreamNext::Continue
                    });
                }
            };
        drop(up_reader);

        if (200..300).contains(&resp_head.status) || resp_head.status == 304 {
            let inspect_json = match self.fetch_container_inspect(version_prefix, raw_id).await {
                Ok(json) => json,
                Err(err) => {
                    let close = req.wants_close();
                    write_json_error(client, 502, "Bad Gateway", &err, close)
                        .await
                        .map_err(http_to_io)?;
                    return Ok(if close {
                        StreamNext::Close
                    } else {
                        StreamNext::Continue
                    });
                }
            };

            if let Err(err) = self
                .registry
                .activate_container_forwards(
                    Arc::clone(&self.tunnel_port),
                    &self.sandbox_id,
                    id,
                    &inspect_json,
                )
                .await
            {
                let close = req.wants_close();
                write_json_error(
                    client,
                    500,
                    "Internal Server Error",
                    &err.to_string(),
                    close,
                )
                .await
                .map_err(http_to_io)?;
                return Ok(if close {
                    StreamNext::Close
                } else {
                    StreamNext::Continue
                });
            }
        }

        write_buffered_response(client, req, &mut resp_head, &resp_body).await
    }

    async fn handle_stop_kill_or_delete<S>(
        &self,
        client: &mut PrefixedReader<S>,
        req: &HttpRequestHead,
        id: &str,
        is_delete: bool,
    ) -> io::Result<StreamNext>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let mut up_reader = match self.forward_request_to_upstream(client, req).await {
            Ok(reader) => reader,
            Err(err_next) => return err_next,
        };

        let (mut resp_head, resp_body) =
            match read_buffered_upstream_response(&mut up_reader, &req.method).await {
                Ok(res) => res,
                Err(err) => {
                    let close = req.wants_close();
                    write_json_error(client, 502, "Bad Gateway", &err.to_string(), close)
                        .await
                        .map_err(http_to_io)?;
                    return Ok(if close {
                        StreamNext::Close
                    } else {
                        StreamNext::Continue
                    });
                }
            };
        drop(up_reader);

        let should_release = if is_delete {
            (200..300).contains(&resp_head.status)
                || resp_head.status == 404
                || query_has_truthy_param(req.query.as_deref(), "force")
        } else {
            (200..300).contains(&resp_head.status) || resp_head.status == 304
        };

        if should_release {
            let forget = is_delete
                && ((200..300).contains(&resp_head.status) || resp_head.status == 404);
            self.registry
                .release_container_forwards_async(id, forget)
                .await;
        }

        write_buffered_response(client, req, &mut resp_head, &resp_body).await
    }

    async fn handle_container_inspect<S>(
        &self,
        client: &mut PrefixedReader<S>,
        req: &HttpRequestHead,
        id: &str,
    ) -> io::Result<StreamNext>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let mut up_reader = match self.forward_request_to_upstream(client, req).await {
            Ok(reader) => reader,
            Err(err_next) => return err_next,
        };

        let mut resp_head = match read_non_1xx_response_head(&mut up_reader, Some(client)).await {
            Ok(head) => head,
            Err(err) => {
                let close = req.wants_close();
                write_json_error(client, 502, "Bad Gateway", &err.to_string(), close)
                    .await
                    .map_err(http_to_io)?;
                return Ok(if close {
                    StreamNext::Close
                } else {
                    StreamNext::Continue
                });
            }
        };

        if resp_head.status == 200 {
            let raw_body = match read_body_bytes(
                &mut up_reader,
                resp_head.body_mode(&req.method),
                MAX_BUFFERED_BODY_BYTES,
            )
            .await
            {
                Ok(body) => body,
                Err(err) => {
                    let close = req.wants_close();
                    write_json_error(client, 502, "Bad Gateway", &err.to_string(), close)
                        .await
                        .map_err(http_to_io)?;
                    return Ok(if close {
                        StreamNext::Close
                    } else {
                        StreamNext::Continue
                    });
                }
            };

            let mut forwards = self.registry.snapshot_for_container(id);
            if forwards.is_empty() {
                if let Ok(parsed) = serde_json::from_slice::<Value>(&raw_body) {
                    if let Some(canonical_id) = parsed.get("Id").and_then(Value::as_str) {
                        forwards = self.registry.snapshot_for_container(canonical_id);
                    }
                    if forwards.is_empty() {
                        if let Some(name) = parsed.get("Name").and_then(Value::as_str) {
                            forwards = self.registry.snapshot_for_container(name);
                        }
                    }
                }
            }

            let rewritten = match rewrite_container_inspect_json(&raw_body, &forwards) {
                Ok(bytes) => bytes,
                Err(err) => {
                    let close = req.wants_close();
                    write_json_error(client, 502, "Bad Gateway", &err.to_string(), close)
                        .await
                        .map_err(http_to_io)?;
                    return Ok(if close {
                        StreamNext::Close
                    } else {
                        StreamNext::Continue
                    });
                }
            };

            return write_buffered_response(client, req, &mut resp_head, &rewritten).await;
        }

        stream_upstream_response(client, req, up_reader, resp_head).await
    }

    async fn handle_containers_list<S>(
        &self,
        client: &mut PrefixedReader<S>,
        req: &HttpRequestHead,
    ) -> io::Result<StreamNext>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let mut up_reader = match self.forward_request_to_upstream(client, req).await {
            Ok(reader) => reader,
            Err(err_next) => return err_next,
        };

        let mut resp_head = match read_non_1xx_response_head(&mut up_reader, Some(client)).await {
            Ok(head) => head,
            Err(err) => {
                let close = req.wants_close();
                write_json_error(client, 502, "Bad Gateway", &err.to_string(), close)
                    .await
                    .map_err(http_to_io)?;
                return Ok(if close {
                    StreamNext::Close
                } else {
                    StreamNext::Continue
                });
            }
        };

        if resp_head.status == 200 {
            let raw_body = match read_body_bytes(
                &mut up_reader,
                resp_head.body_mode(&req.method),
                MAX_BUFFERED_BODY_BYTES,
            )
            .await
            {
                Ok(body) => body,
                Err(err) => {
                    let close = req.wants_close();
                    write_json_error(client, 502, "Bad Gateway", &err.to_string(), close)
                        .await
                        .map_err(http_to_io)?;
                    return Ok(if close {
                        StreamNext::Close
                    } else {
                        StreamNext::Continue
                    });
                }
            };

            let rewritten = match rewrite_containers_list_json(&raw_body, &self.registry) {
                Ok(bytes) => bytes,
                Err(err) => {
                    let close = req.wants_close();
                    write_json_error(client, 502, "Bad Gateway", &err.to_string(), close)
                        .await
                        .map_err(http_to_io)?;
                    return Ok(if close {
                        StreamNext::Close
                    } else {
                        StreamNext::Continue
                    });
                }
            };

            return write_buffered_response(client, req, &mut resp_head, &rewritten).await;
        }

        stream_upstream_response(client, req, up_reader, resp_head).await
    }

    async fn handle_passthrough_or_hijack<S>(
        &self,
        client: &mut PrefixedReader<S>,
        req: &HttpRequestHead,
    ) -> io::Result<StreamNext>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let mut up_reader = match self.forward_request_to_upstream(client, req).await {
            Ok(reader) => reader,
            Err(err_next) => return err_next,
        };

        let resp_head = match read_non_1xx_response_head(&mut up_reader, Some(client)).await {
            Ok(head) => head,
            Err(err) => {
                let close = req.wants_close();
                write_json_error(client, 502, "Bad Gateway", &err.to_string(), close)
                    .await
                    .map_err(http_to_io)?;
                return Ok(if close {
                    StreamNext::Close
                } else {
                    StreamNext::Continue
                });
            }
        };

        stream_upstream_response(client, req, up_reader, resp_head).await
    }

    async fn forward_request_to_upstream<S>(
        &self,
        client: &mut PrefixedReader<S>,
        req: &HttpRequestHead,
    ) -> Result<PrefixedReader<TunnelStream>, io::Result<StreamNext>>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let body_mode = req.body_mode();
        let mut upstream = match self
            .tunnel_port
            .open_podman_unix_stream(&self.sandbox_id)
            .await
        {
            Ok(stream) => stream,
            Err(err) => {
                let close = should_close_rejected_request(req, false);
                let res = write_json_error(client, 502, "Bad Gateway", &err.to_string(), close)
                    .await
                    .map_err(http_to_io);
                return Err(res.map(|()| {
                    if close {
                        StreamNext::Close
                    } else {
                        StreamNext::Continue
                    }
                }));
            }
        };

        let up_req = match prepare_expect_header(client, req).await {
            Ok(Some(prepared)) => prepared,
            Ok(None) => return Err(Ok(StreamNext::Close)),
            Err(err) => return Err(Err(err)),
        };

        if let Err(err) = write_request_head(&mut upstream, &up_req).await {
            let close = should_close_rejected_request(req, false);
            let res = write_json_error(client, 502, "Bad Gateway", &err.to_string(), close)
                .await
                .map_err(http_to_io);
            return Err(res.map(|()| {
                if close {
                    StreamNext::Close
                } else {
                    StreamNext::Continue
                }
            }));
        }

        if let Err(err) = forward_body(client, &mut upstream, body_mode).await {
            match err {
                HttpError::InvalidChunk(_) | HttpError::MalformedHead(_) => {
                    let _ = write_json_error(client, 400, "Bad Request", &err.to_string(), true)
                        .await;
                    return Err(Ok(StreamNext::Close));
                }
                HttpError::Io(io_err) => {
                    let mut up_reader = PrefixedReader::new(upstream);
                    if let Ok(Ok(mut resp_head)) = tokio::time::timeout(
                        Duration::from_secs(2),
                        read_non_1xx_response_head::<tokio::io::Sink>(&mut up_reader, None),
                    )
                    .await
                    {
                        let allow_body = response_allows_body(&req.method, resp_head.status);
                        let resp_body = if allow_body {
                            match tokio::time::timeout(
                                Duration::from_secs(2),
                                read_body_bytes(
                                    &mut up_reader,
                                    resp_head.body_mode(&req.method),
                                    MAX_BUFFERED_BODY_BYTES,
                                ),
                            )
                            .await
                            {
                                Ok(Ok(body)) => body,
                                _ => Vec::new(),
                            }
                        } else {
                            Vec::new()
                        };
                        set_buffered_body_headers(
                            &mut resp_head.headers,
                            resp_body.len(),
                            allow_body,
                        );
                        ensure_connection_close_if(true, &mut resp_head);
                        if write_response_head(client, &resp_head).await.is_ok() {
                            if allow_body && !resp_body.is_empty() {
                                let _ = client.write_all(&resp_body).await;
                            }
                            let _ = client.flush().await;
                        }
                        return Err(Ok(StreamNext::Close));
                    }
                    let _ = write_json_error(
                        client,
                        502,
                        "Bad Gateway",
                        &io_err.to_string(),
                        true,
                    )
                    .await;
                    return Err(Ok(StreamNext::Close));
                }
                _ => {
                    let _ = write_json_error(client, 502, "Bad Gateway", &err.to_string(), true)
                        .await;
                    return Err(Ok(StreamNext::Close));
                }
            }
        }

        Ok(PrefixedReader::new(upstream))
    }

    async fn fetch_container_inspect(
        &self,
        version_prefix: Option<&str>,
        raw_id: &str,
    ) -> Result<Value, String> {
        let inspect_path = match version_prefix {
            Some(prefix) => format!("{prefix}/containers/{raw_id}/json"),
            None => format!("/containers/{raw_id}/json"),
        };
        let inspect_req = HttpRequestHead {
            method: "GET".to_owned(),
            raw_target: inspect_path.clone(),
            path: inspect_path,
            query: None,
            version: "HTTP/1.1".to_owned(),
            headers: vec![("Host".to_owned(), "localhost".to_owned())],
        };

        let mut upstream = self
            .tunnel_port
            .open_podman_unix_stream(&self.sandbox_id)
            .await
            .map_err(|err| format!("failed to open Podman stream for inspect: {err}"))?;

        write_request_head(&mut upstream, &inspect_req)
            .await
            .map_err(|err| format!("failed to write inspect request: {err}"))?;

        let mut up_reader = PrefixedReader::new(upstream);
        let (head, body) = read_buffered_upstream_response(&mut up_reader, "GET")
            .await
            .map_err(|err| format!("failed to read inspect response: {err}"))?;

        if head.status != 200 {
            return Err(format!(
                "Podman inspect returned HTTP {} {}",
                head.status, head.reason
            ));
        }
        serde_json::from_slice(&body)
            .map_err(|err| format!("invalid Podman inspect JSON: {err}"))
    }
}

fn should_close_rejected_request(req: &HttpRequestHead, body_consumed: bool) -> bool {
    req.wants_close()
        || req.wants_upgrade()
        || (!body_consumed && !matches!(req.body_mode(), BodyMode::Empty))
}

async fn stream_upstream_response<S>(
    client: &mut PrefixedReader<S>,
    req: &HttpRequestHead,
    mut up_reader: PrefixedReader<TunnelStream>,
    mut resp_head: HttpResponseHead,
) -> io::Result<StreamNext>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    if resp_head.is_upgrade() {
        write_response_head(client, &resp_head)
            .await
            .map_err(http_to_io)?;
        let (upstream_stream, upstream_pre_buf) = up_reader.into_parts();
        return Ok(StreamNext::Hijacked {
            upstream_stream,
            upstream_pre_buf,
        });
    }

    let resp_mode = resp_head.body_mode(&req.method);
    let close =
        req.wants_close() || resp_head.wants_close() || resp_mode == BodyMode::UntilEof;
    ensure_connection_close_if(close, &mut resp_head);

    write_response_head(client, &resp_head)
        .await
        .map_err(http_to_io)?;
    forward_body(&mut up_reader, client, resp_mode)
        .await
        .map_err(http_to_io)?;
    client.flush().await?;

    Ok(if close {
        StreamNext::Close
    } else {
        StreamNext::Continue
    })
}

async fn write_buffered_response<S>(
    client: &mut PrefixedReader<S>,
    req: &HttpRequestHead,
    resp_head: &mut HttpResponseHead,
    body: &[u8],
) -> io::Result<StreamNext>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let allow_body = response_allows_body(&req.method, resp_head.status);
    set_buffered_body_headers(&mut resp_head.headers, body.len(), allow_body);
    let close = req.wants_close() || resp_head.wants_close();
    ensure_connection_close_if(close, resp_head);

    write_response_head(client, resp_head)
        .await
        .map_err(http_to_io)?;
    if allow_body && !body.is_empty() {
        client.write_all(body).await?;
    }
    client.flush().await?;

    Ok(if close {
        StreamNext::Close
    } else {
        StreamNext::Continue
    })
}

async fn read_non_1xx_response_head<W: AsyncWrite + Unpin>(
    up_reader: &mut PrefixedReader<TunnelStream>,
    mut client_for_1xx: Option<&mut W>,
) -> Result<HttpResponseHead, HttpError> {
    loop {
        let head = read_response_head(up_reader).await?;
        if (100..=199).contains(&head.status) && !head.is_upgrade() {
            if let Some(client) = client_for_1xx.as_deref_mut() {
                write_response_head(client, &head).await?;
            }
            continue;
        }
        return Ok(head);
    }
}

async fn read_buffered_upstream_response(
    up_reader: &mut PrefixedReader<TunnelStream>,
    request_method: &str,
) -> Result<(HttpResponseHead, Vec<u8>), HttpError> {
    let head = read_non_1xx_response_head::<tokio::io::Sink>(up_reader, None).await?;
    let body = read_body_bytes(up_reader, head.body_mode(request_method), MAX_BUFFERED_BODY_BYTES)
        .await?;
    Ok((head, body))
}

async fn write_request_and_bytes<W: AsyncWrite + Unpin>(
    writer: &mut W,
    head: &HttpRequestHead,
    body: &[u8],
) -> Result<(), HttpError> {
    write_request_head(writer, head).await?;
    if !body.is_empty() {
        writer.write_all(body).await?;
        writer.flush().await?;
    }
    Ok(())
}

fn canonicalize_docker_path(raw_path: &str) -> Result<String, &'static str> {
    if !raw_path.starts_with('/') || raw_path.contains('\\') || raw_path.contains('\0') {
        return Err("invalid Docker API request path");
    }

    let mut segments = Vec::new();
    for raw_seg in raw_path.split('/') {
        if raw_seg.is_empty() {
            continue;
        }
        let bytes = raw_seg.as_bytes();
        let mut norm = String::with_capacity(bytes.len());
        let mut i = 0usize;
        while i < bytes.len() {
            if bytes[i] == b'%' {
                if i + 2 >= bytes.len() {
                    return Err("malformed percent-encoding in Docker API path");
                }
                let (Some(hi), Some(lo)) = (hex_nibble(bytes[i + 1]), hex_nibble(bytes[i + 2]))
                else {
                    return Err("malformed percent-encoding in Docker API path");
                };
                let decoded = (hi << 4) | lo;
                if decoded <= 0x1F || decoded == 0x7F || decoded == b'\\' {
                    return Err("forbidden encoded character in Docker API path");
                }
                if decoded.is_ascii_alphanumeric()
                    || matches!(decoded, b'-' | b'.' | b'_' | b'~')
                {
                    norm.push(decoded as char);
                } else {
                    const HEX: &[u8; 16] = b"0123456789ABCDEF";
                    norm.push('%');
                    norm.push(HEX[(decoded >> 4) as usize] as char);
                    norm.push(HEX[(decoded & 0x0F) as usize] as char);
                }
                i += 3;
            } else {
                if bytes[i] <= 0x1F || bytes[i] == 0x7F {
                    return Err("control character in Docker API path");
                }
                let ch = raw_seg[i..]
                    .chars()
                    .next()
                    .ok_or("invalid UTF-8 in Docker API path")?;
                norm.push(ch);
                i += ch.len_utf8();
            }
        }
        if norm == "." || norm == ".." {
            return Err("dot segments in Docker API path are forbidden");
        }
        segments.push(norm);
    }

    if let Some(first) = segments.first() {
        if looks_like_version_prefix_attempt(first) {
            if !is_api_version_segment(first) {
                return Err("malformed Docker API version prefix");
            }
            segments[0].make_ascii_lowercase();
        }
    }

    let tail_start = usize::from(
        segments
            .first()
            .is_some_and(|first| is_api_version_segment(first)),
    );
    let tail = &segments[tail_start..];
    for (idx, seg) in tail.iter().enumerate() {
        if seg.contains("%2F") {
            let is_image_ref = idx == 1 && tail[0].eq_ignore_ascii_case("images");
            if !is_image_ref {
                return Err("encoded slash '%2F' is forbidden in this Docker API route");
            }
            if !seg
                .split("%2F")
                .all(|sub| !sub.is_empty() && sub != "." && sub != "..")
            {
                return Err("invalid subsegment in encoded Docker image name");
            }
        }
    }

    if segments.is_empty() {
        Ok("/".to_owned())
    } else {
        Ok(format!("/{}", segments.join("/")))
    }
}

fn parse_docker_route<'a>(method: &str, path: &'a str) -> DockerRoute<'a> {
    let (version_prefix, normalized) = strip_api_version(path);
    let trimmed = normalized.trim_start_matches('/');
    if trimmed.is_empty() {
        return DockerRoute::PassThrough;
    }
    let parts: Vec<&str> = trimmed.split('/').collect();
    for (idx, seg) in parts.iter().enumerate() {
        let is_image_ref = idx == 1 && parts[0].eq_ignore_ascii_case("images");
        if !is_image_ref && seg.eq_ignore_ascii_case("libpod") {
            return DockerRoute::ForbiddenLibpod;
        }
    }

    match parts[0].to_ascii_lowercase().as_str() {
        "plugins" => {
            return DockerRoute::ForbiddenRoute(
                "Docker plugins API is disabled on the sandbox compatibility endpoint",
            );
        }
        "swarm" | "nodes" | "services" | "tasks" | "secrets" | "configs" => {
            return DockerRoute::ForbiddenRoute(
                "Docker Swarm/cluster API is disabled on the sandbox compatibility endpoint",
            );
        }
        "grpc" | "session" => {
            return DockerRoute::ForbiddenRoute(
                "BuildKit gRPC/session API is disabled on the sandbox compatibility endpoint",
            );
        }
        _ => {}
    }

    if method.eq_ignore_ascii_case("POST") {
        match parts.as_slice() {
            [c, action]
                if c.eq_ignore_ascii_case("containers")
                    && action.eq_ignore_ascii_case("create") =>
            {
                return DockerRoute::ContainerCreate;
            }
            [v, action]
                if v.eq_ignore_ascii_case("volumes")
                    && action.eq_ignore_ascii_case("create") =>
            {
                return DockerRoute::VolumeCreate;
            }
            [n, action]
                if n.eq_ignore_ascii_case("networks")
                    && action.eq_ignore_ascii_case("create") =>
            {
                return DockerRoute::NetworkCreate;
            }
            [n, raw_id, action]
                if n.eq_ignore_ascii_case("networks")
                    && action.eq_ignore_ascii_case("connect") =>
            {
                return match decode_safe_container_id(raw_id) {
                    Some(id) => DockerRoute::NetworkConnect { id },
                    None => DockerRoute::ForbiddenRoute(
                        "invalid network identifier in Docker API path",
                    ),
                };
            }
            [c, raw_id, action]
                if c.eq_ignore_ascii_case("containers")
                    && action.eq_ignore_ascii_case("exec") =>
            {
                return match decode_safe_container_id(raw_id) {
                    Some(_) => DockerRoute::ContainerExecCreate,
                    None => DockerRoute::ForbiddenRoute(
                        "invalid container identifier in Docker API path",
                    ),
                };
            }
            [c, _, action]
                if c.eq_ignore_ascii_case("containers")
                    && action.eq_ignore_ascii_case("update") =>
            {
                return DockerRoute::ForbiddenRoute(
                    "POST /containers/{id}/update is disabled on the sandbox compatibility endpoint",
                );
            }
            [b] if b.eq_ignore_ascii_case("build") => {
                return DockerRoute::ImageBuild;
            }
            [images, create]
                if images.eq_ignore_ascii_case("images") && create.eq_ignore_ascii_case("create") =>
            {
                return DockerRoute::ImageCreate;
            }
            [c, raw_id, action]
                if c.eq_ignore_ascii_case("containers")
                    && action.eq_ignore_ascii_case("start") =>
            {
                if let Some(id) = decode_safe_container_id(raw_id) {
                    return DockerRoute::ContainerStart {
                        version_prefix,
                        raw_id,
                        id,
                    };
                }
            }
            [c, raw_id, action]
                if c.eq_ignore_ascii_case("containers")
                    && action.eq_ignore_ascii_case("restart") =>
            {
                if let Some(id) = decode_safe_container_id(raw_id) {
                    return DockerRoute::ContainerRestart {
                        version_prefix,
                        raw_id,
                        id,
                    };
                }
            }
            [c, raw_id, action]
                if c.eq_ignore_ascii_case("containers")
                    && action.eq_ignore_ascii_case("stop") =>
            {
                if let Some(id) = decode_safe_container_id(raw_id) {
                    return DockerRoute::ContainerStop { id };
                }
            }
            [c, raw_id, action]
                if c.eq_ignore_ascii_case("containers")
                    && action.eq_ignore_ascii_case("kill") =>
            {
                if let Some(id) = decode_safe_container_id(raw_id) {
                    return DockerRoute::ContainerKill { id };
                }
            }
            [e, raw_id, action]
                if e.eq_ignore_ascii_case("exec") && action.eq_ignore_ascii_case("start") =>
            {
                if decode_safe_container_id(raw_id).is_some() {
                    return DockerRoute::ExecOrAttachHijack;
                }
            }
            [c, raw_id, action]
                if c.eq_ignore_ascii_case("containers")
                    && action.eq_ignore_ascii_case("attach")
                    && decode_safe_container_id(raw_id).is_some() =>
            {
                return DockerRoute::ExecOrAttachHijack;
            }
            _ => {}
        }
    } else if method.eq_ignore_ascii_case("GET") {
        match parts.as_slice() {
            [c, j]
                if c.eq_ignore_ascii_case("containers") && j.eq_ignore_ascii_case("json") =>
            {
                return DockerRoute::ContainerList;
            }
            [c, raw_id, j]
                if c.eq_ignore_ascii_case("containers") && j.eq_ignore_ascii_case("json") =>
            {
                if let Some(id) = decode_safe_container_id(raw_id) {
                    return DockerRoute::ContainerInspect { id };
                }
            }
            _ => {}
        }
    } else if method.eq_ignore_ascii_case("DELETE") {
        if let [c, raw_id] = parts.as_slice() {
            if c.eq_ignore_ascii_case("containers") && !raw_id.eq_ignore_ascii_case("prune") {
                if let Some(id) = decode_safe_container_id(raw_id) {
                    return DockerRoute::ContainerDelete { id };
                }
            }
        }
    }

    DockerRoute::PassThrough
}

fn strip_api_version(path: &str) -> (Option<&str>, &str) {
    let Some(rest) = path.strip_prefix('/') else {
        return (None, path);
    };
    let Some((first_seg, tail)) = rest.split_once('/') else {
        return (None, path);
    };
    if is_api_version_segment(first_seg) {
        let prefix_len = 1 + first_seg.len();
        let _ = tail;
        (Some(&path[..prefix_len]), &path[prefix_len..])
    } else {
        (None, path)
    }
}

fn looks_like_version_prefix_attempt(seg: &str) -> bool {
    let bytes = seg.as_bytes();
    bytes.len() >= 2
        && matches!(bytes[0], b'v' | b'V')
        && bytes[1].is_ascii_digit()
}

fn is_api_version_segment(seg: &str) -> bool {
    let Some(ver) = seg.strip_prefix('v').or_else(|| seg.strip_prefix('V')) else {
        return false;
    };
    let bytes = ver.as_bytes();
    if bytes.is_empty()
        || !ver.contains('.')
        || !bytes.first().is_some_and(u8::is_ascii_digit)
        || !bytes.last().is_some_and(u8::is_ascii_digit)
    {
        return false;
    }
    bytes.iter().all(|b| b.is_ascii_digit() || *b == b'.') && !ver.contains("..")
}

fn decode_safe_container_id(raw: &str) -> Option<String> {
    if raw.is_empty() {
        return None;
    }
    let decoded = percent_decode(raw);
    let trimmed = decoded.trim();
    if trimmed.is_empty()
        || trimmed == "."
        || trimmed == ".."
        || trimmed.contains('/')
        || trimmed.contains('\0')
    {
        return None;
    }
    Some(trimmed.to_owned())
}

#[cfg(windows)]
async fn reopen_docker_pipe_with_backoff<F>(
    pipe_name: &str,
    create_pipe: &mut F,
    shutdown_rx: &mut watch::Receiver<bool>,
) -> Option<tokio::net::windows::named_pipe::NamedPipeServer>
where
    F: FnMut(
        &str,
        bool,
    ) -> Result<tokio::net::windows::named_pipe::NamedPipeServer, SandboxError>,
{
    let mut delay = DOCKER_ACCEPT_RETRY_BACKOFF;
    loop {
        tokio::select! {
            biased;
            _ = shutdown_rx.wait_for(|done| *done) => return None,
            _ = tokio::time::sleep(delay) => {}
        }
        if let Ok(next) = create_pipe(pipe_name, false).or_else(|_| create_pipe(pipe_name, true)) {
            return Some(next);
        }
        delay = (delay * 2).min(Duration::from_millis(250));
    }
}

fn decode_all_query_params(query: Option<&str>) -> Vec<(String, String)> {
    let Some(q) = query else {
        return Vec::new();
    };
    q.split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| {
            let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
            (percent_decode(k), percent_decode(v))
        })
        .collect()
}

fn extract_query_param(query: Option<&str>, key: &str) -> Option<String> {
    let q = query?;
    for pair in q.split('&') {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        if percent_decode(k) == key {
            let decoded = percent_decode(v);
            if !decoded.is_empty() {
                return Some(decoded);
            }
        }
    }
    None
}

fn query_has_truthy_param(query: Option<&str>, key: &str) -> bool {
    let Some(val) = extract_query_param(query, key) else {
        return false;
    };
    val == "1" || val.eq_ignore_ascii_case("true")
}

fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(hi), Some(lo)) = (hex_nibble(bytes[i + 1]), hex_nibble(bytes[i + 2])) {
                out.push((hi << 4) | lo);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

async fn prepare_expect_header<S>(
    client: &mut PrefixedReader<S>,
    req: &HttpRequestHead,
) -> io::Result<Option<HttpRequestHead>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut has_100_continue = false;
    for (k, v) in &req.headers {
        if k.eq_ignore_ascii_case("expect") {
            let trimmed = v.trim();
            if trimmed.eq_ignore_ascii_case("100-continue") {
                has_100_continue = true;
            } else if !trimmed.is_empty() {
                write_json_error(
                    client,
                    417,
                    "Expectation Failed",
                    &format!("unsupported Expect header value '{trimmed}'"),
                    true,
                )
                .await
                .map_err(http_to_io)?;
                return Ok(None);
            }
        }
    }

    if has_100_continue
        && req.version == "HTTP/1.1"
        && !matches!(req.body_mode(), BodyMode::Empty)
    {
        client.write_all(b"HTTP/1.1 100 Continue\r\n\r\n").await?;
        client.flush().await?;
    }

    let mut up_req = req.clone();
    up_req.version = "HTTP/1.1".to_owned();
    strip_headers(&mut up_req.headers, &["expect"]);
    Ok(Some(up_req))
}

fn response_allows_body(request_method: &str, status: u16) -> bool {
    !request_method.eq_ignore_ascii_case("HEAD")
        && !(100..=199).contains(&status)
        && status != 204
        && status != 304
}

fn strip_headers(headers: &mut Vec<(String, String)>, names: &[&str]) {
    headers.retain(|(k, _)| !names.iter().any(|n| k.eq_ignore_ascii_case(n)));
}

fn set_buffered_body_headers(
    headers: &mut Vec<(String, String)>,
    body_len: usize,
    allow_body: bool,
) {
    strip_headers(headers, &["content-length", "transfer-encoding"]);
    if allow_body {
        headers.push(("Content-Length".to_owned(), body_len.to_string()));
    }
}

fn ensure_connection_close_if(close: bool, resp_head: &mut HttpResponseHead) {
    if close && resp_head.version == "HTTP/1.1" && !resp_head.wants_close() {
        resp_head
            .headers
            .push(("Connection".to_owned(), "close".to_owned()));
    }
}

fn http_to_io(err: HttpError) -> io::Error {
    match err {
        HttpError::Io(io_err) => io_err,
        other => io::Error::new(io::ErrorKind::InvalidData, other),
    }
}

#[cfg(unix)]
mod unix_acl {
    use std::fs::{self, DirBuilder, OpenOptions};
    use std::io;
    use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, OpenOptionsExt};
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    use sandbox_core::SandboxError;

    pub(super) fn ensure_owner_only_dir(path: &Path) -> Result<(), SandboxError> {
        match DirBuilder::new().mode(0o700).create(path) {
            Ok(()) => {}
            Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {}
            Err(err) => {
                return Err(SandboxError::Transport(format!(
                    "failed to create owner-only socket directory '{}': {err}",
                    path.display()
                )));
            }
        }

        let meta = fs::symlink_metadata(path).map_err(|err| {
            SandboxError::Transport(format!(
                "failed to inspect socket directory '{}': {err}",
                path.display()
            ))
        })?;
        if meta.file_type().is_symlink() {
            return Err(SandboxError::PolicyViolation(format!(
                "refusing Unix socket directory '{}': symlinks are not allowed",
                path.display()
            )));
        }
        if !meta.is_dir() {
            return Err(SandboxError::PolicyViolation(format!(
                "refusing Unix socket directory '{}': path is not a directory",
                path.display()
            )));
        }

        let mode = meta.mode() & 0o777;
        if mode != 0o700 {
            return Err(SandboxError::PolicyViolation(format!(
                "Unix socket directory '{}' has insecure mode {:04o}, expected 0700",
                path.display(),
                mode
            )));
        }

        let expected_uid = current_uid()?;
        if meta.uid() != expected_uid {
            return Err(SandboxError::PolicyViolation(format!(
                "Unix socket directory '{}' is owned by uid {}, expected uid {}",
                path.display(),
                meta.uid(),
                expected_uid
            )));
        }

        Ok(())
    }

    pub(super) fn remove_stale_socket_if_safe(socket_path: &Path) -> Result<(), SandboxError> {
        let meta = match fs::symlink_metadata(socket_path) {
            Ok(meta) => meta,
            Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(err) => {
                return Err(SandboxError::Transport(format!(
                    "failed to inspect existing path '{}': {err}",
                    socket_path.display()
                )));
            }
        };

        if meta.file_type().is_symlink() || meta.is_dir() || !meta.file_type().is_socket() {
            return Err(SandboxError::PolicyViolation(format!(
                "refusing to remove non-socket or symlink at '{}'",
                socket_path.display()
            )));
        }
        let expected_uid = current_uid()?;
        if meta.uid() != expected_uid {
            return Err(SandboxError::PolicyViolation(format!(
                "refusing to remove stale socket '{}' owned by uid {} (expected {})",
                socket_path.display(),
                meta.uid(),
                expected_uid
            )));
        }

        fs::remove_file(socket_path).map_err(|err| {
            SandboxError::Transport(format!(
                "failed to remove stale socket '{}': {err}",
                socket_path.display()
            ))
        })
    }

    fn current_uid() -> Result<u32, SandboxError> {
        #[cfg(target_os = "linux")]
        if let Ok(meta) = fs::metadata("/proc/self") {
            return Ok(meta.uid());
        }

        static SEQ: AtomicU64 = AtomicU64::new(0);
        struct ProbeCleanup(PathBuf);
        impl Drop for ProbeCleanup {
            fn drop(&mut self) {
                let _ = fs::remove_file(&self.0);
            }
        }

        let tmp_dir = std::env::temp_dir();
        for _ in 0..8 {
            let seq = SEQ.fetch_add(1, Ordering::Relaxed);
            let probe_path = tmp_dir.join(format!("mp-dc-uid-{}-{seq}", std::process::id()));
            match OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&probe_path)
            {
                Ok(file) => {
                    let _cleanup = ProbeCleanup(probe_path);
                    let meta = file.metadata().map_err(|err| {
                        SandboxError::Internal(format!("failed to read UID probe metadata: {err}"))
                    })?;
                    return Ok(meta.uid());
                }
                Err(err) if err.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(err) => {
                    return Err(SandboxError::Internal(format!(
                        "failed to determine current UID via temp probe '{}': {err}",
                        probe_path.display()
                    )));
                }
            }
        }

        Err(SandboxError::Internal(
            "exhausted retries while creating UID probe file".to_owned(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Mutex;
    use std::time::Duration;

    use crate::policy::ReaperSocketPolicy;
    use sandbox_core::{DestroyStatus, ExecRequest, SandboxLease, SandboxSpec};
    use sandbox_protocol::StreamId;
    use sandbox_runtime::{ExecStream, RuntimeManager, TunnelStreamHandle};
    use serde_json::json;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;
    use tokio::sync::Notify;

    const CONTAINER_ID: &str =
        "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";

    #[derive(Default)]
    struct MockContainerState {
        name: Option<String>,
        guest_port: u16,
        started: bool,
        create_bodies: Vec<Value>,
        request_log: Vec<String>,
    }

    struct MockPodmanTunnelPort {
        next_stream_id: AtomicU32,
        state: Arc<Mutex<MockContainerState>>,
        log_release_notify: Arc<Notify>,
    }

    impl MockPodmanTunnelPort {
        fn new() -> Self {
            Self {
                next_stream_id: AtomicU32::new(1),
                state: Arc::new(Mutex::new(MockContainerState {
                    guest_port: 44100,
                    ..MockContainerState::default()
                })),
                log_release_notify: Arc::new(Notify::new()),
            }
        }

        fn next_id(&self) -> StreamId {
            StreamId(self.next_stream_id.fetch_add(1, Ordering::Relaxed))
        }
    }

    #[async_trait::async_trait]
    impl RuntimeManager for MockPodmanTunnelPort {
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
    impl SandboxTunnelPort for MockPodmanTunnelPort {
        async fn open_podman_unix_stream(
            &self,
            _id: &SandboxId,
        ) -> Result<TunnelStream, SandboxError> {
            let (stream, handle): (TunnelStream, TunnelStreamHandle) =
                TunnelStream::channel(self.next_id());
            let state = Arc::clone(&self.state);
            let log_notify = Arc::clone(&self.log_release_notify);

            tokio::spawn(async move {
                let mut reader = PrefixedReader::new(handle.read_half);
                let mut writer = handle.write_half;
                let _drop_rx = handle.drop_rx;

                let Some(req) = read_request_head(&mut reader).await.unwrap_or(None) else {
                    return;
                };
                let body = read_body_bytes(&mut reader, req.body_mode(), MAX_BUFFERED_BODY_BYTES)
                    .await
                    .unwrap_or_default();

                let (_, norm_path) = strip_api_version(&req.path);
                {
                    let mut guard = state.lock().unwrap();
                    guard
                        .request_log
                        .push(format!("{} {}", req.method, req.raw_target));
                }

                if req.method == "GET" && norm_path == "/_ping" {
                    let _ = write_simple_resp(&mut writer, 200, "OK", "text/plain", b"OK").await;
                    return;
                }
                if req.method == "GET" && norm_path == "/version" {
                    let payload = br#"{"Version":"24.0.0","ApiVersion":"1.45"}"#;
                    let _ =
                        write_simple_resp(&mut writer, 200, "OK", "application/json", payload)
                            .await;
                    return;
                }
                if req.method == "POST" && norm_path == "/containers/create" {
                    let parsed: Value = serde_json::from_slice(&body).unwrap();
                    let name = extract_query_param(req.query.as_deref(), "name");
                    {
                        let mut guard = state.lock().unwrap();
                        guard.name = name;
                        guard.create_bodies.push(parsed);
                    }
                    let resp = serde_json::to_vec(&json!({
                        "Id": CONTAINER_ID,
                        "Warnings": []
                    }))
                    .unwrap();
                    let _ = write_simple_resp(
                        &mut writer,
                        201,
                        "Created",
                        "application/json",
                        &resp,
                    )
                    .await;
                    return;
                }
                if req.method == "POST"
                    && (norm_path.ends_with("/start") || norm_path.ends_with("/restart"))
                    && norm_path.starts_with("/containers/")
                {
                    {
                        let mut guard = state.lock().unwrap();
                        guard.started = true;
                        if norm_path.ends_with("/restart") {
                            guard.guest_port += 1;
                        }
                    }
                    let _ = write_no_content(&mut writer, 204, "No Content").await;
                    return;
                }
                if (req.method == "POST"
                    && (norm_path.ends_with("/stop") || norm_path.ends_with("/kill")))
                    || req.method == "DELETE"
                {
                    {
                        let mut guard = state.lock().unwrap();
                        guard.started = false;
                    }
                    let _ = write_no_content(&mut writer, 204, "No Content").await;
                    return;
                }
                if req.method == "GET" && norm_path == "/containers/json" {
                    let (name, guest_port, started) = {
                        let guard = state.lock().unwrap();
                        (
                            guard.name.clone().unwrap_or_else(|| "app".to_owned()),
                            guard.guest_port,
                            guard.started,
                        )
                    };
                    let ports = if started {
                        json!([{
                            "IP": "127.0.0.1",
                            "PrivatePort": 8080,
                            "PublicPort": guest_port,
                            "Type": "tcp"
                        }])
                    } else {
                        json!([])
                    };
                    let payload = serde_json::to_vec(&json!([{
                        "Id": CONTAINER_ID,
                        "Names": [format!("/{name}")],
                        "Image": "nginx:alpine",
                        "State": if started { "running" } else { "exited" },
                        "Ports": ports
                    }]))
                    .unwrap();
                    let _ = write_simple_resp(
                        &mut writer,
                        200,
                        "OK",
                        "application/json",
                        &payload,
                    )
                    .await;
                    return;
                }
                if req.method == "GET"
                    && norm_path.starts_with("/containers/")
                    && norm_path.ends_with("/json")
                {
                    let (name, guest_port, started) = {
                        let guard = state.lock().unwrap();
                        (
                            guard.name.clone().unwrap_or_else(|| "app".to_owned()),
                            guard.guest_port,
                            guard.started,
                        )
                    };
                    let ports = if started {
                        json!({
                            "8080/tcp": [{ "HostIp": "127.0.0.1", "HostPort": guest_port.to_string() }]
                        })
                    } else {
                        json!({})
                    };
                    let payload = serde_json::to_vec(&json!({
                        "Id": CONTAINER_ID,
                        "Name": format!("/{name}"),
                        "Config": { "Image": "nginx:alpine" },
                        "HostConfig": {
                            "PortBindings": {
                                "8080/tcp": [{ "HostIp": "127.0.0.1", "HostPort": "" }]
                            }
                        },
                        "NetworkSettings": {
                            "IPAddress": "10.88.0.5",
                            "Ports": ports
                        }
                    }))
                    .unwrap();
                    let _ = write_simple_resp(
                        &mut writer,
                        200,
                        "OK",
                        "application/json",
                        &payload,
                    )
                    .await;
                    return;
                }
                if req.method == "POST"
                    && norm_path.starts_with("/exec/")
                    && norm_path.ends_with("/start")
                {
                    let head_bytes = b"HTTP/1.1 101 UPGRADED\r\nContent-Type: application/vnd.docker.raw-stream\r\nConnection: Upgrade\r\nUpgrade: tcp\r\n\r\npre-out:";
                    writer.write_all(head_bytes).await.unwrap();
                    writer.flush().await.unwrap();

                    let (mut raw_read, pre_in) = reader.into_parts();
                    let mut collected = pre_in;
                    raw_read.read_to_end(&mut collected).await.unwrap();

                    let mut resp = b"echo:".to_vec();
                    resp.extend_from_slice(&collected);
                    writer.write_all(&resp).await.unwrap();
                    writer.flush().await.unwrap();
                    writer.shutdown().await.unwrap();
                    return;
                }
                if req.method == "GET" && norm_path.ends_with("/logs") {
                    let head = b"HTTP/1.1 200 OK\r\nContent-Type: application/vnd.docker.raw-stream\r\nTransfer-Encoding: chunked\r\n\r\n";
                    writer.write_all(head).await.unwrap();
                    writer.write_all(b"e\r\nREADY_ON_8080\n\r\n").await.unwrap();
                    writer.flush().await.unwrap();

                    log_notify.notified().await;

                    writer.write_all(b"5\r\ndone\n\r\n0\r\n\r\n").await.unwrap();
                    writer.flush().await.unwrap();
                    return;
                }

                let _ = write_simple_resp(
                    &mut writer,
                    404,
                    "Not Found",
                    "application/json",
                    br#"{"message":"not found"}"#,
                )
                .await;
            });

            Ok(stream)
        }

        async fn open_guest_tcp_stream(
            &self,
            _id: &SandboxId,
            guest_port: u16,
        ) -> Result<TunnelStream, SandboxError> {
            let expected = self.state.lock().unwrap().guest_port;
            if guest_port != expected {
                return Err(SandboxError::Transport(format!(
                    "unexpected guest_port {guest_port}, expected {expected}"
                )));
            }
            let (stream, handle): (TunnelStream, TunnelStreamHandle) =
                TunnelStream::channel(self.next_id());
            tokio::spawn(async move {
                let mut reader = handle.read_half;
                let mut writer = handle.write_half;
                let _drop_rx = handle.drop_rx;

                let mut buf = [0u8; 1024];
                let n = reader.read(&mut buf).await.unwrap_or(0);
                if n > 0 {
                    let reply = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\nguest:{}",
                        n + 6,
                        String::from_utf8_lossy(&buf[..n])
                    );
                    let _ = writer.write_all(reply.as_bytes()).await;
                    let _ = writer.flush().await;
                }
                let _ = writer.shutdown().await;
            });
            Ok(stream)
        }
    }

    async fn write_simple_resp<W: AsyncWrite + Unpin>(
        writer: &mut W,
        status: u16,
        reason: &str,
        content_type: &str,
        body: &[u8],
    ) -> io::Result<()> {
        let head = format!(
            "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\n\r\n",
            body.len()
        );
        writer.write_all(head.as_bytes()).await?;
        writer.write_all(body).await?;
        writer.flush().await
    }

    async fn write_no_content<W: AsyncWrite + Unpin>(
        writer: &mut W,
        status: u16,
        reason: &str,
    ) -> io::Result<()> {
        let head = format!("HTTP/1.1 {status} {reason}\r\n\r\n");
        writer.write_all(head.as_bytes()).await?;
        writer.flush().await
    }

    async fn send_http(
        reader: &mut PrefixedReader<TcpStream>,
        method: &str,
        target: &str,
        body: Option<&[u8]>,
    ) -> (HttpResponseHead, Vec<u8>) {
        let mut raw = format!("{method} {target} HTTP/1.1\r\nHost: localhost\r\n");
        if let Some(b) = body {
            raw.push_str(&format!(
                "Content-Type: application/json\r\nContent-Length: {}\r\n",
                b.len()
            ));
        }
        raw.push_str("\r\n");
        reader.write_all(raw.as_bytes()).await.unwrap();
        if let Some(b) = body {
            reader.write_all(b).await.unwrap();
        }
        reader.flush().await.unwrap();

        let head = read_response_head(reader).await.unwrap();
        let resp_body = read_body_bytes(reader, head.body_mode(method), MAX_BUFFERED_BODY_BYTES)
            .await
            .unwrap();
        (head, resp_body)
    }

    #[tokio::test]
    async fn end_to_end_docker_compat_lifecycle_port_forward_rewrite_hijack_and_streaming() {
        let mock = Arc::new(MockPodmanTunnelPort::new());
        let tunnel: Arc<dyn SandboxTunnelPort> = Arc::clone(&mock) as Arc<dyn SandboxTunnelPort>;
        let server = Arc::new(DockerCompatServer::new(
            tunnel,
            SandboxId::new("sbx-docker-e2e"),
            DockerCompatPolicy {
                reaper_socket: ReaperSocketPolicy::MapGuestPodmanSocket,
                ..Default::default()
            },
        ));

        // 1. Non-loopback TCP bind is strictly rejected.
        let non_loopback: SocketAddr = "0.0.0.0:0".parse().unwrap();
        assert!(matches!(
            server.bind_loopback_http(non_loopback).await,
            Err(SandboxError::PolicyViolation(_))
        ));

        let handle = server
            .bind_loopback_http("127.0.0.1:0".parse().unwrap())
            .await
            .expect("bind loopback HTTP server");
        let addr = handle.local_addr();

        // 2. Policy rejection (raw C:\ bind) returns 400 JSON WITHOUT touching Podman!
        let mut conn = PrefixedReader::new(TcpStream::connect(addr).await.unwrap());
        let bad_create = serde_json::to_vec(&json!({
            "Image": "alpine",
            "HostConfig": { "Binds": ["C:\\Users\\alice:/data"] }
        }))
        .unwrap();
        let (bad_head, bad_body) =
            send_http(&mut conn, "POST", "/v1.45/containers/create", Some(&bad_create)).await;
        assert_eq!(bad_head.status, 400);
        assert_eq!(bad_head.header("content-type"), Some("application/json"));
        let bad_json: Value = serde_json::from_slice(&bad_body).unwrap();
        assert!(bad_json["message"].as_str().unwrap().contains("forbidden"));
        assert!(mock.state.lock().unwrap().request_log.is_empty());

        // 3. HTTP/1.1 keep-alive pipelined sequential requests on the SAME socket:
        //    GET /_ping -> GET /version -> POST /v1.45/containers/create?name=web-demo
        let create_payload = serde_json::to_vec(&json!({
            "Image": "nginx:alpine",
            "ExposedPorts": { "8080/tcp": {} },
            "HostConfig": {
                "Binds": ["/var/run/docker.sock:/var/run/docker.sock:ro"],
                "PortBindings": {
                    "8080/tcp": [{ "HostIp": "0.0.0.0", "HostPort": "" }]
                }
            }
        }))
        .unwrap();
        let pipelined = format!(
            "GET /_ping HTTP/1.1\r\nHost: localhost\r\n\r\n\
             GET /v1.45/version HTTP/1.1\r\nHost: localhost\r\n\r\n\
             POST /v1.45/containers/create?name=web-demo HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
            create_payload.len()
        );
        conn.write_all(pipelined.as_bytes()).await.unwrap();
        conn.write_all(&create_payload).await.unwrap();
        conn.flush().await.unwrap();

        let (h1, b1) = {
            let h = read_response_head(&mut conn).await.unwrap();
            let b = read_body_bytes(&mut conn, h.body_mode("GET"), 1024).await.unwrap();
            (h, b)
        };
        assert_eq!(h1.status, 200);
        assert_eq!(b1, b"OK");

        let (h2, b2) = {
            let h = read_response_head(&mut conn).await.unwrap();
            let b = read_body_bytes(&mut conn, h.body_mode("GET"), 1024).await.unwrap();
            (h, b)
        };
        assert_eq!(h2.status, 200);
        let v_json: Value = serde_json::from_slice(&b2).unwrap();
        assert_eq!(v_json["ApiVersion"], "1.45");

        let (h3, b3) = {
            let h = read_response_head(&mut conn).await.unwrap();
            let b = read_body_bytes(&mut conn, h.body_mode("POST"), 4096).await.unwrap();
            (h, b)
        };
        assert_eq!(h3.status, 201);
        let c_json: Value = serde_json::from_slice(&b3).unwrap();
        assert_eq!(c_json["Id"], CONTAINER_ID);

        // Verify Podman received rewritten Ryuk socket bind & loopback ephemeral PortBindings.
        {
            let guard = mock.state.lock().unwrap();
            assert_eq!(guard.create_bodies.len(), 1);
            assert_eq!(
                guard.create_bodies[0]["HostConfig"]["Binds"][0],
                "/run/podman/podman.sock:/var/run/docker.sock:ro"
            );
            assert_eq!(
                guard.create_bodies[0]["HostConfig"]["PortBindings"]["8080/tcp"],
                json!([{ "HostIp": "127.0.0.1", "HostPort": "" }])
            );
        }

        // 4. POST /start binds a real host TCP port; inspect & list rewrite to that host port.
        let (start_head, _) = send_http(&mut conn, "POST", "/v1.45/containers/web-demo/start", None).await;
        assert_eq!(start_head.status, 204);

        let short_id = &CONTAINER_ID[..12];
        let (insp_head, insp_body) =
            send_http(&mut conn, "GET", &format!("/v1.45/containers/{short_id}/json"), None).await;
        assert_eq!(insp_head.status, 200);
        let insp_json: Value = serde_json::from_slice(&insp_body).unwrap();
        assert_eq!(insp_json["NetworkSettings"]["IPAddress"], "10.88.0.5");
        let host_port: u16 = insp_json["NetworkSettings"]["Ports"]["8080/tcp"][0]["HostPort"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap();
        assert_ne!(host_port, 44100);
        assert_eq!(
            insp_json["HostConfig"]["PortBindings"]["8080/tcp"][0]["HostPort"],
            host_port.to_string()
        );

        let (list_head, list_body) = send_http(&mut conn, "GET", "/v1.45/containers/json", None).await;
        assert_eq!(list_head.status, 200);
        let list_json: Value = serde_json::from_slice(&list_body).unwrap();
        assert_eq!(list_json[0]["Ports"][0]["PublicPort"], host_port);
        assert_eq!(list_json[0]["Ports"][0]["PrivatePort"], 8080);

        // Live TCP request through the forwarded host TCP port reaches guest_port 44100!
        let mut fwd_tcp = TcpStream::connect(("127.0.0.1", host_port)).await.unwrap();
        fwd_tcp.write_all(b"ping").await.unwrap();
        let mut fwd_resp = Vec::new();
        fwd_tcp.read_to_end(&mut fwd_resp).await.unwrap();
        assert!(String::from_utf8_lossy(&fwd_resp).ends_with("guest:ping"));

        // 4b. POST /restart tears down old forward and rebinds onto bumped guest_port (44101).
        let (restart_head, _) =
            send_http(&mut conn, "POST", "/v1.45/containers/web-demo/restart", None).await;
        assert_eq!(restart_head.status, 204);
        let (_, insp_after_restart) =
            send_http(&mut conn, "GET", &format!("/v1.45/containers/{short_id}/json"), None).await;
        let restart_json: Value = serde_json::from_slice(&insp_after_restart).unwrap();
        let restarted_host_port: u16 = restart_json["NetworkSettings"]["Ports"]["8080/tcp"][0]["HostPort"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap();
        let mut fwd_restarted = TcpStream::connect(("127.0.0.1", restarted_host_port))
            .await
            .unwrap();
        fwd_restarted.write_all(b"pong").await.unwrap();
        let mut restarted_resp = Vec::new();
        fwd_restarted.read_to_end(&mut restarted_resp).await.unwrap();
        assert!(String::from_utf8_lossy(&restarted_resp).ends_with("guest:pong"));

        // 4c. POST /stop frees the host port, and subsequent POST /start activates again.
        let (stop_head, _) =
            send_http(&mut conn, "POST", "/v1.45/containers/web-demo/stop", None).await;
        assert_eq!(stop_head.status, 204);
        assert!(TcpStream::connect(("127.0.0.1", restarted_host_port))
            .await
            .is_err());
        let (restart2_head, _) =
            send_http(&mut conn, "POST", "/v1.45/containers/web-demo/start", None).await;
        assert_eq!(restart2_head.status, 204);
        let (_, insp_after_start2) =
            send_http(&mut conn, "GET", &format!("/v1.45/containers/{short_id}/json"), None).await;
        let start2_json: Value = serde_json::from_slice(&insp_after_start2).unwrap();
        let host_port = start2_json["NetworkSettings"]["Ports"]["8080/tcp"][0]["HostPort"]
            .as_str()
            .unwrap()
            .parse::<u16>()
            .unwrap();

        // 5. GET /logs?follow=1 streams first chunk immediately without stalling!
        let mut logs_conn = PrefixedReader::new(TcpStream::connect(addr).await.unwrap());
        logs_conn
            .write_all(
                format!(
                    "GET /v1.45/containers/{short_id}/logs?follow=1 HTTP/1.1\r\nHost: localhost\r\n\r\n"
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        logs_conn.flush().await.unwrap();

        let logs_head = read_response_head(&mut logs_conn).await.unwrap();
        assert_eq!(logs_head.status, 200);
        assert!(logs_head.is_chunked());

        // Wait for the first chunk BEFORE notifying mock Podman to send the rest!
        let mut first_chunk_buf = Vec::new();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        while !String::from_utf8_lossy(&first_chunk_buf).contains("READY_ON_8080\n") {
            assert!(tokio::time::Instant::now() < deadline, "timed out waiting for streamed chunk");
            let mut tmp = [0u8; 64];
            let n = logs_conn.read(&mut tmp).await.unwrap();
            assert!(n > 0);
            first_chunk_buf.extend_from_slice(&tmp[..n]);
        }
        mock.log_release_notify.notify_one();

        let mut rest_logs = first_chunk_buf;
        while !rest_logs.windows(5).any(|w| w == b"0\r\n\r\n") {
            let mut tmp = [0u8; 64];
            let n = logs_conn.read(&mut tmp).await.unwrap();
            if n == 0 {
                break;
            }
            rest_logs.extend_from_slice(&tmp[..n]);
        }
        assert!(String::from_utf8_lossy(&rest_logs).contains("done\n"));
        drop(logs_conn);

        // 6. POST /exec/:id/start 101 UPGRADED half-close hijack with pre-buffered stdin & stdout!
        let mut exec_conn = TcpStream::connect(addr).await.unwrap();
        let exec_body = br#"{"Detach":false,"Tty":false}"#;
        let exec_req = format!(
            "POST /v1.45/exec/exec-1/start HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: Upgrade\r\nUpgrade: tcp\r\n\r\n",
            exec_body.len()
        );
        exec_conn.write_all(exec_req.as_bytes()).await.unwrap();
        exec_conn.write_all(exec_body).await.unwrap();
        // Immediately pipeline stdin before 101 arrives to exercise pre_buf!
        exec_conn.write_all(b"pre-in:").await.unwrap();
        exec_conn.flush().await.unwrap();

        let mut exec_reader = PrefixedReader::new(exec_conn);
        let upg_head = read_response_head(&mut exec_reader).await.unwrap();
        assert!(upg_head.is_upgrade());
        assert_eq!(upg_head.status, 101);

        let (mut raw_exec, pre_out) = exec_reader.into_parts();
        raw_exec.write_all(b"more-stdin").await.unwrap();
        raw_exec.shutdown().await.unwrap();

        let mut all_exec_out = pre_out;
        raw_exec.read_to_end(&mut all_exec_out).await.unwrap();
        assert_eq!(all_exec_out, b"pre-out:echo:pre-in:more-stdin");

        // 7. DELETE /containers/:id releases the bound host TCP port cleanly.
        let (del_head, _) = send_http(&mut conn, "DELETE", "/v1.45/containers/web-demo?force=true", None).await;
        assert_eq!(del_head.status, 204);
        assert!(TcpStream::connect(("127.0.0.1", host_port)).await.is_err());

        drop(conn);
        handle.shutdown().await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn unix_owner_only_socket_sets_0700_and_0600_rejects_symlinks_and_cleans_up() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        use tokio::net::UnixStream;

        let mock = Arc::new(MockPodmanTunnelPort::new());
        let tunnel: Arc<dyn SandboxTunnelPort> = mock;
        let server = Arc::new(DockerCompatServer::new(
            tunnel,
            SandboxId::new("sbx-unix"),
            DockerCompatPolicy::default(),
        ));

        let run_dir = std::env::temp_dir().join(format!("mp-dc-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&run_dir);
        let sock_path = run_dir.join("docker.sock");

        let handle = server
            .bind_unix_owner_only(&sock_path)
            .await
            .expect("bind owner-only Unix socket");

        let dir_meta = std::fs::symlink_metadata(&run_dir).unwrap();
        assert_eq!(dir_meta.permissions().mode() & 0o777, 0o700);
        let sock_meta = std::fs::symlink_metadata(&sock_path).unwrap();
        assert_eq!(sock_meta.permissions().mode() & 0o777, 0o600);

        let mut client = PrefixedReader::new(UnixStream::connect(&sock_path).await.unwrap());
        client
            .write_all(b"GET /_ping HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();
        client.flush().await.unwrap();
        let head = read_response_head(&mut client).await.unwrap();
        let body = read_body_bytes(&mut client, head.body_mode("GET"), 1024)
            .await
            .unwrap();
        assert_eq!(head.status, 200);
        assert_eq!(body, b"OK");
        drop(client);

        handle.shutdown().await;
        assert!(!sock_path.exists());

        // Symlink at socket path must be rejected.
        let target = run_dir.join("target");
        std::fs::write(&target, b"x").unwrap();
        symlink(&target, &sock_path).unwrap();
        assert!(matches!(
            server.bind_unix_owner_only(&sock_path).await,
            Err(SandboxError::PolicyViolation(_))
        ));
        let _ = std::fs::remove_file(&sock_path);

        // Weak directory permissions (0755) must be rejected.
        std::fs::set_permissions(&run_dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(matches!(
            server.bind_unix_owner_only(&sock_path).await,
            Err(SandboxError::PolicyViolation(_))
        ));

        let _ = std::fs::remove_dir_all(&run_dir);
    }

    #[test]
    fn strip_api_version_and_route_matching_cover_edge_cases() {
        assert_eq!(
            strip_api_version("/v1.45/containers/create"),
            (Some("/v1.45"), "/containers/create")
        );
        assert_eq!(strip_api_version("/v1.43/_ping"), (Some("/v1.43"), "/_ping"));
        assert_eq!(strip_api_version("/version"), (None, "/version"));
        assert_eq!(strip_api_version("/v1..2/containers/json"), (None, "/v1..2/containers/json"));
        assert_eq!(strip_api_version("/v1./containers/json"), (None, "/v1./containers/json"));

        assert!(matches!(
            parse_docker_route("GET", "/v1.45/containers/json"),
            DockerRoute::ContainerList
        ));
        assert!(matches!(
            parse_docker_route("GET", "/v1.45/containers/abc123/json"),
            DockerRoute::ContainerInspect { ref id } if id == "abc123"
        ));
        assert!(matches!(
            parse_docker_route("DELETE", "/containers/prune"),
            DockerRoute::PassThrough
        ));
        assert!(matches!(
            parse_docker_route("DELETE", "/containers/my%2Dbox"),
            DockerRoute::ContainerDelete { ref id } if id == "my-box"
        ));

        // Double slashes and percent-encoded unreserved literals canonicalize before routing.
        assert_eq!(
            canonicalize_docker_path("//v1.45//containers//%63reate").unwrap(),
            "/v1.45/containers/create"
        );
        assert!(matches!(
            parse_docker_route(
                "POST",
                &canonicalize_docker_path("//v1.45//containers//%63reate").unwrap()
            ),
            DockerRoute::ContainerCreate
        ));

        // Preserves %2F inside image references while rejecting dot segments and /libpod.
        assert_eq!(
            canonicalize_docker_path("/v1.45/images/minipod-e2e%2fecho-http:1.0/json").unwrap(),
            "/v1.45/images/minipod-e2e%2Fecho-http:1.0/json"
        );
        assert!(canonicalize_docker_path("/containers/./create").is_err());
        assert!(canonicalize_docker_path("/containers/%2e%2e/create").is_err());
        assert!(canonicalize_docker_path("/containers/a%00b/json").is_err());
        assert!(canonicalize_docker_path("/containers/a%5cb/json").is_err());

        assert!(matches!(
            parse_docker_route(
                "POST",
                &canonicalize_docker_path("/v5.0.0/%6cibpod/containers/create").unwrap()
            ),
            DockerRoute::ForbiddenLibpod
        ));

        // Uppercase API version prefixes normalize to lowercase before route matching.
        let upper_create = canonicalize_docker_path("/V1.45/containers/create").unwrap();
        assert_eq!(upper_create, "/v1.45/containers/create");
        assert!(matches!(
            parse_docker_route("POST", &upper_create),
            DockerRoute::ContainerCreate
        ));
        let upper_libpod = canonicalize_docker_path("/V5.0.0/libpod/containers/create").unwrap();
        assert_eq!(upper_libpod, "/v5.0.0/libpod/containers/create");
        assert!(matches!(
            parse_docker_route("POST", &upper_libpod),
            DockerRoute::ForbiddenLibpod
        ));
        assert_eq!(
            canonicalize_docker_path("/V1.45/images/minipod-e2e%2fecho-http:1.0/json").unwrap(),
            "/v1.45/images/minipod-e2e%2Fecho-http:1.0/json"
        );

        // Encoded slashes `%2F` outside valid `/images/<ref>` segments are rejected cleanly.
        for bad_encoded_slash in [
            "/v1.45/containers%2Fcreate",
            "/v5.0.0/libpod%2Fcontainers%2Fcreate",
            "/libpod%2fcontainers/create",
            "/v1.45/containers/abc%2Fstart",
            "/v1.45/images/..%2Flibpod/json",
        ] {
            assert!(
                canonicalize_docker_path(bad_encoded_slash).is_err(),
                "must reject encoded slash route '{bad_encoded_slash}'"
            );
        }

        // Malformed gorilla/mux version prefixes (`/v1.45-0/...`, `/v1/...`) must fail closed.
        for bad_ver in [
            "/v1.45-0/containers/create",
            "/v1/containers/create",
            "/V1.45_rc1/containers/create",
            "/v1..45/containers/create",
        ] {
            assert!(
                canonicalize_docker_path(bad_ver).is_err(),
                "must reject malformed version prefix '{bad_ver}'"
            );
        }

        // Non-leading `/libpod` segments must be blocked, while `/images/libpod/json` remains valid.
        assert!(matches!(
            parse_docker_route("GET", "/v1.45/containers/libpod/json"),
            DockerRoute::ForbiddenLibpod
        ));
        assert!(!matches!(
            parse_docker_route("GET", "/v1.45/images/libpod/json"),
            DockerRoute::ForbiddenLibpod
        ));
    }

    #[tokio::test]
    async fn router_closes_on_rejected_unconsumed_body_and_enforces_mutating_route_policies() {
        let tunnel_port: Arc<dyn SandboxTunnelPort> = Arc::new(MockPodmanTunnelPort::new());
        let server = Arc::new(DockerCompatServer::new(
            tunnel_port,
            SandboxId::new("sb-route-gates"),
            DockerCompatPolicy::default(),
        ));
        let handle = server
            .bind_loopback_http("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let addr = handle.local_addr();

        // 1. `POST /v5.0.0/libpod/containers/create` with a body must return 403 AND close the
        // connection so unconsumed body bytes cannot smuggle a second request on keep-alive.
        {
            let mut conn = tokio::net::TcpStream::connect(addr).await.unwrap();
            let smuggled = concat!(
                "POST /v5.0.0/libpod/containers/create HTTP/1.1\r\n",
                "Host: localhost\r\n",
                "Content-Length: 37\r\n\r\n",
                "GET /_ping HTTP/1.1\r\nHost: localhost\r\n"
            );
            conn.write_all(smuggled.as_bytes()).await.unwrap();
            let mut reader = PrefixedReader::new(conn);
            let head = read_response_head(&mut reader).await.unwrap();
            assert_eq!(head.status, 403);
            assert!(
                head.wants_close(),
                "ForbiddenLibpod response with unread body must signal Connection: close"
            );
            let _ = read_body_bytes(&mut reader, head.body_mode("POST"), 4096)
                .await
                .unwrap();
            assert!(
                read_response_head(&mut reader).await.is_err(),
                "connection must be closed rather than parsing unread body as pipelined GET /_ping"
            );
        }

        // 2. Malformed version prefix, volume bind opts, privileged exec, host network connect, and
        // `POST /build?networkmode=host` must all fail closed with 400 over HTTP.
        for (path, body) in [
            (
                "/v1.45-0/containers/create",
                r#"{"Image":"alpine","HostConfig":{"Privileged":true}}"#,
            ),
            (
                "/v1.45/volumes/create",
                r#"{"Name":"v1","DriverOpts":{"type":"none","o":"bind","device":"/"}}"#,
            ),
            (
                "/v1.45/containers/ctr123/exec",
                r#"{"Cmd":["/bin/sh"],"Privileged":true}"#,
            ),
            (
                "/v1.45/networks/create",
                r#"{"Name":"host","Driver":"bridge"}"#,
            ),
            ("/v1.45/networks/host/connect", r#"{"Container":"ctr123"}"#),
            ("/v1.45/build?networkmode=host", "tar-stream-bytes"),
            ("/v1.45/build?volume=/:/host", "tar-stream-bytes"),
        ] {
            let conn = tokio::net::TcpStream::connect(addr).await.unwrap();
            let mut reader = PrefixedReader::new(conn);
            let (head, _) = send_http(&mut reader, "POST", path, Some(body.as_bytes())).await;
            assert_eq!(
                head.status, 400,
                "expected 400 Bad Request on '{path}', got {}",
                head.status
            );
        }

        // 3. Admin/cluster/plugin/BuildKit/container-update endpoints must return 403 Forbidden.
        for (method, path, body) in [
            ("GET", "/v1.45/plugins", None),
            ("POST", "/v1.45/plugins/pull?remote=evil", Some(&b"{}"[..])),
            ("POST", "/v1.45/swarm/init", Some(&b"{}"[..])),
            ("GET", "/v1.45/secrets", None),
            ("POST", "/grpc", Some(&b"frame"[..])),
            ("POST", "/v1.45/containers/ctr123/update", Some(&b"{\"Privileged\":true}"[..])),
        ] {
            let conn = tokio::net::TcpStream::connect(addr).await.unwrap();
            let mut reader = PrefixedReader::new(conn);
            let (head, _) = send_http(&mut reader, method, path, body).await;
            assert_eq!(
                head.status, 403,
                "expected 403 Forbidden on '{method} {path}', got {}",
                head.status
            );
        }

        handle.shutdown().await;
    }

    #[tokio::test]
    async fn expect_headers_early_upstream_rejection_and_images_create_fromsrc_policy() {
        struct ScriptedTunnelPort {
            next_id: AtomicU32,
            captured_expect_headers: Arc<Mutex<Vec<Option<String>>>>,
            early_reject_large_uploads: bool,
        }

        impl ScriptedTunnelPort {
            fn new(early_reject_large_uploads: bool) -> Self {
                Self {
                    next_id: AtomicU32::new(1),
                    captured_expect_headers: Arc::new(Mutex::new(Vec::new())),
                    early_reject_large_uploads,
                }
            }
        }

        #[async_trait::async_trait]
        impl RuntimeManager for ScriptedTunnelPort {
            async fn spawn(&self, _spec: SandboxSpec) -> Result<SandboxLease, SandboxError> {
                unreachable!()
            }
            async fn renew_lease(
                &self,
                _id: &SandboxId,
                _ttl: Duration,
            ) -> Result<(), SandboxError> {
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
        impl SandboxTunnelPort for ScriptedTunnelPort {
            async fn open_guest_tcp_stream(
                &self,
                _id: &SandboxId,
                _guest_port: u16,
            ) -> Result<TunnelStream, SandboxError> {
                unreachable!()
            }

            async fn open_podman_unix_stream(
                &self,
                _id: &SandboxId,
            ) -> Result<TunnelStream, SandboxError> {
                let id = StreamId(self.next_id.fetch_add(1, Ordering::Relaxed));
                let (stream, handle): (TunnelStream, TunnelStreamHandle) = TunnelStream::channel(id);
                let captured = Arc::clone(&self.captured_expect_headers);
                let early_reject = self.early_reject_large_uploads;
                tokio::spawn(async move {
                    let mut reader = PrefixedReader::new(handle.read_half);
                    let mut writer = handle.write_half;
                    let _drop_rx = handle.drop_rx;

                    let Some(req) = read_request_head(&mut reader).await.unwrap_or(None) else {
                        return;
                    };
                    captured
                        .lock()
                        .unwrap()
                        .push(req.header("expect").map(str::to_owned));

                    if early_reject {
                        // Read only a small prefix, then reply HTTP 400 and close upstream early.
                        let mut small = [0u8; 64];
                        let _ = reader.read(&mut small).await;
                        let body = br#"{"message":"early upstream rejection"}"#;
                        let head = format!(
                            "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
                            body.len()
                        );
                        let _ = writer.write_all(head.as_bytes()).await;
                        let _ = writer.write_all(body).await;
                        let _ = writer.flush().await;
                        let _ = writer.shutdown().await;
                        return;
                    }

                    let _ = read_body_bytes(&mut reader, req.body_mode(), MAX_BUFFERED_BODY_BYTES)
                        .await
                        .unwrap_or_default();
                    let body = br#"{"Id":"ctr-ok","Warnings":[]}"#;
                    let _ = write_simple_resp(&mut writer, 200, "OK", "application/json", body).await;
                });
                Ok(stream)
            }
        }

        // Part A: `Expect: 100-continue` on sanitized JSON and passthrough, plus `Expect: bad` -> 417
        // and `POST /images/create?fromSrc=/etc/passwd` -> 400.
        let tunnel_impl = Arc::new(ScriptedTunnelPort::new(false));
        let server = Arc::new(DockerCompatServer::new(
            Arc::clone(&tunnel_impl) as Arc<dyn SandboxTunnelPort>,
            SandboxId::new("sbx-expect"),
            DockerCompatPolicy::default(),
        ));
        let handle = server
            .bind_loopback_http("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let addr = handle.local_addr();

        // 1. Unsupported Expect token returns 417 without reaching upstream.
        let mut bad_expect_conn = PrefixedReader::new(TcpStream::connect(addr).await.unwrap());
        bad_expect_conn
            .write_all(
                b"POST /v1.45/images/create?fromSrc=- HTTP/1.1\r\nHost: localhost\r\nExpect: weird\r\nContent-Length: 4\r\n\r\n",
            )
            .await
            .unwrap();
        bad_expect_conn.flush().await.unwrap();
        let head_417 = read_response_head(&mut bad_expect_conn).await.unwrap();
        assert_eq!(head_417.status, 417);
        assert!(head_417.wants_close());

        // 2. `POST /images/create?fromSrc=/etc/passwd` is rejected 400 before opening upstream.
        let mut from_src_conn = PrefixedReader::new(TcpStream::connect(addr).await.unwrap());
        let (head_from_src, _) = send_http(
            &mut from_src_conn,
            "POST",
            "/v1.45/images/create?fromSrc=/etc/passwd",
            None,
        )
        .await;
        assert_eq!(head_from_src.status, 400);
        assert!(tunnel_impl.captured_expect_headers.lock().unwrap().is_empty());

        // 3. `Expect: 100-continue` on sanitized JSON `POST /containers/create`: sends 100 Continue
        // and strips Expect before upstream receives request.
        let mut json_100 = PrefixedReader::new(TcpStream::connect(addr).await.unwrap());
        let json_body = br#"{"Image":"alpine"}"#;
        let json_head = format!(
            "POST /v1.45/containers/create HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nExpect: 100-continue\r\nContent-Length: {}\r\n\r\n",
            json_body.len()
        );
        json_100.write_all(json_head.as_bytes()).await.unwrap();
        json_100.flush().await.unwrap();
        let interim = read_response_head(&mut json_100).await.unwrap();
        assert_eq!(interim.status, 100);
        json_100.write_all(json_body).await.unwrap();
        json_100.flush().await.unwrap();
        let final_head = read_response_head(&mut json_100).await.unwrap();
        assert_eq!(final_head.status, 200);
        let _ = read_body_bytes(&mut json_100, final_head.body_mode("POST"), 4096)
            .await
            .unwrap();

        // 4. `Expect: 100-continue` on passthrough streaming `POST /images/create?fromSrc=-`.
        let mut pass_100 = PrefixedReader::new(TcpStream::connect(addr).await.unwrap());
        pass_100
            .write_all(
                b"POST /v1.45/images/create?fromSrc=- HTTP/1.1\r\nHost: localhost\r\nExpect: 100-continue\r\nContent-Length: 5\r\n\r\n",
            )
            .await
            .unwrap();
        pass_100.flush().await.unwrap();
        let pass_interim = read_response_head(&mut pass_100).await.unwrap();
        assert_eq!(pass_interim.status, 100);
        pass_100.write_all(b"hello").await.unwrap();
        pass_100.flush().await.unwrap();
        let pass_final = read_response_head(&mut pass_100).await.unwrap();
        assert_eq!(pass_final.status, 200);
        let _ = read_body_bytes(&mut pass_100, pass_final.body_mode("POST"), 4096)
            .await
            .unwrap();

        {
            let recorded = tunnel_impl.captured_expect_headers.lock().unwrap();
            assert_eq!(recorded.as_slice(), &[None, None]);
        }
        handle.shutdown().await;

        // Part B: early upstream 400 response during a >64 KiB upload is forwarded to the client.
        let early_tunnel = Arc::new(ScriptedTunnelPort::new(true));
        let early_server = Arc::new(DockerCompatServer::new(
            Arc::clone(&early_tunnel) as Arc<dyn SandboxTunnelPort>,
            SandboxId::new("sbx-early-reject"),
            DockerCompatPolicy::default(),
        ));
        let early_handle = early_server
            .bind_loopback_http("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();

        let mut upload_conn =
            PrefixedReader::new(TcpStream::connect(early_handle.local_addr()).await.unwrap());
        let big_len = 256 * 1024;
        let head = format!(
            "POST /v1.45/images/create?fromSrc=- HTTP/1.1\r\nHost: localhost\r\nContent-Length: {big_len}\r\n\r\n"
        );
        upload_conn.write_all(head.as_bytes()).await.unwrap();
        upload_conn.flush().await.unwrap();
        let writer_handle = tokio::spawn(async move {
            let chunk = vec![b'a'; 16 * 1024];
            let mut written = 0usize;
            while written < big_len {
                if upload_conn.write_all(&chunk).await.is_err() {
                    break;
                }
                written += chunk.len();
                tokio::task::yield_now().await;
            }
            let _ = upload_conn.flush().await;
            let resp_head = read_response_head(&mut upload_conn).await.unwrap();
            let resp_body = read_body_bytes(&mut upload_conn, resp_head.body_mode("POST"), 4096)
                .await
                .unwrap();
            (resp_head, resp_body)
        });
        let (early_head, early_body) = writer_handle.await.unwrap();
        assert_eq!(early_head.status, 400);
        assert!(early_head.wants_close());
        assert!(String::from_utf8_lossy(&early_body).contains("early upstream rejection"));
        early_handle.shutdown().await;
    }
}
