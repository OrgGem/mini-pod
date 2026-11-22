//! CLI configuration, environment defaults, and strict control-endpoint policy checks for `sandboxd`.

use std::fs::OpenOptions;
use std::io::Read;
use std::path::PathBuf;
use std::time::Duration;

use sandbox_client::{ControlEndpoint, DEFAULT_MAX_COPY_BYTES};
use sandbox_core::safe_tar::{apply_open_no_follow, reject_symlink_or_reparse};
use sandbox_core::{
    AccelerationPolicy, GuestArch, IsolationMode, NetworkPolicy, ResourceBudget, SandboxError,
    SandboxSpec,
};
use sandbox_image::{decode_hex_exact, BundleVerifier};
use sandbox_runtime::{AdmissionLimits, RuntimeManagerConfig, WarmPoolConfig};

pub const USAGE_TEXT: &str = "\
mini-pod local sandbox daemon & MCP server

USAGE:
    sandboxd serve [OPTIONS]
    sandboxd mcp (--connect <ENDPOINT> | [SERVE_OPTIONS])
    sandboxd --help

SUBCOMMANDS:
    serve    Run the owner-only local control daemon (Named Pipe / Unix socket)
    mcp      Run an MCP JSON-RPC 2.0 server over stdio (connected or standalone)

SERVE / STANDALONE OPTIONS:
    --bundle-dir <PATH>           Signed Portable Runtime Bundle directory (env: MINIPOD_BUNDLE_DIR)
    --pub-key-hex <HEX>           Ed25519 verifying key hex (64 chars; env: MINIPOD_PUB_KEY_HEX)
    --pub-key-file <PATH>         File containing Ed25519 verifying key hex (env: MINIPOD_PUB_KEY_FILE)
    --state-dir <PATH>            Durable runtime state directory (env: MINIPOD_STATE_DIR)
    --endpoint <URI>              Local control endpoint (unix://... or npipe://...; env: MINIPOD_ENDPOINT)
    --ready-file <PATH>           Write JSON readiness marker atomically after binding (serve only)
    --qemu-bin <PATH>             Explicit qemu-system binary path (env: MINIPOD_QEMU_BIN)
    --qemu-img-bin <PATH>         Explicit qemu-img binary path (env: MINIPOD_QEMU_IMG_BIN)
    --arch <x86_64|aarch64>       Guest architecture (default: host native; env: MINIPOD_ARCH)
    --warm-pool-size <N>          Number of pre-warmed isolated VMs (default: 0)
    --max-sandboxes <N>           Maximum concurrent sandboxes (default: unlimited)
    --max-rss-mb <N>              Maximum total host RSS budget in MiB (default: unlimited)
    --max-storage-mb <N>          Maximum total host storage budget in MiB (default: unlimited)
    --admission-timeout-ms <MS>   FIFO admission queue wait timeout in ms (default: 0)

MCP CONNECT OPTIONS:
    --connect <ENDPOINT>          Connect to an already running sandboxd endpoint

SECURITY:
    --tcp <ADDR>                  Explicitly forbidden (plain TCP without mTLS is rejected)
";

const MAX_PUB_KEY_FILE_BYTES: u64 = 4096;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PubKeySource {
    Embedded,
    Hex(String),
    File(PathBuf),
}

impl PubKeySource {
    /// Loads and validates the configured Ed25519 [`BundleVerifier`].
    pub fn load_verifier(&self) -> Result<BundleVerifier, SandboxError> {
        match self {
            Self::Embedded => BundleVerifier::embedded(),
            Self::Hex(hex) => {
                let key = decode_hex_exact::<32>(hex.trim())?;
                BundleVerifier::with_public_key(key)
            }
            Self::File(path) => {
                let meta = std::fs::symlink_metadata(path).map_err(|err| {
                    SandboxError::InvalidSpec(format!(
                        "failed to inspect pub-key-file '{}': {err}",
                        path.display()
                    ))
                })?;
                reject_symlink_or_reparse(path, &meta)?;
                if !meta.file_type().is_file() {
                    return Err(SandboxError::PolicyViolation(format!(
                        "pub-key-file '{}' must be a regular non-symlink file",
                        path.display()
                    )));
                }
                if meta.len() > MAX_PUB_KEY_FILE_BYTES {
                    return Err(SandboxError::InvalidSpec(format!(
                        "pub-key-file '{}' exceeds {} bytes",
                        path.display(),
                        MAX_PUB_KEY_FILE_BYTES
                    )));
                }
                let mut opts = OpenOptions::new();
                opts.read(true);
                apply_open_no_follow(&mut opts);
                let file = opts.open(path).map_err(|err| {
                    SandboxError::InvalidSpec(format!(
                        "failed to open pub-key-file '{}': {err}",
                        path.display()
                    ))
                })?;
                let open_meta = file.metadata().map_err(|err| {
                    SandboxError::InvalidSpec(format!(
                        "failed to inspect opened pub-key-file '{}': {err}",
                        path.display()
                    ))
                })?;
                reject_symlink_or_reparse(path, &open_meta)?;
                if !open_meta.file_type().is_file() {
                    return Err(SandboxError::PolicyViolation(format!(
                        "pub-key-file '{}' must be a regular non-symlink file",
                        path.display()
                    )));
                }
                if open_meta.len() > MAX_PUB_KEY_FILE_BYTES {
                    return Err(SandboxError::InvalidSpec(format!(
                        "pub-key-file '{}' exceeds {} bytes",
                        path.display(),
                        MAX_PUB_KEY_FILE_BYTES
                    )));
                }
                let mut raw = Vec::with_capacity(open_meta.len() as usize);
                file.take(MAX_PUB_KEY_FILE_BYTES + 1)
                    .read_to_end(&mut raw)
                    .map_err(|err| {
                        SandboxError::InvalidSpec(format!(
                            "failed to read pub-key-file '{}': {err}",
                            path.display()
                        ))
                    })?;
                if (raw.len() as u64) > MAX_PUB_KEY_FILE_BYTES {
                    return Err(SandboxError::InvalidSpec(format!(
                        "pub-key-file '{}' exceeds {} bytes",
                        path.display(),
                        MAX_PUB_KEY_FILE_BYTES
                    )));
                }
                let content = std::str::from_utf8(&raw).map_err(|err| {
                    SandboxError::InvalidSpec(format!(
                        "pub-key-file '{}' is not valid UTF-8: {err}",
                        path.display()
                    ))
                })?;
                let key = decode_hex_exact::<32>(content.trim())?;
                BundleVerifier::with_public_key(key)
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServeConfig {
    pub bundle_dir: PathBuf,
    pub pub_key: PubKeySource,
    pub state_dir: PathBuf,
    pub endpoint: ControlEndpoint,
    pub ready_file: Option<PathBuf>,
    pub qemu_bin: Option<PathBuf>,
    pub qemu_img_bin: Option<PathBuf>,
    pub arch: GuestArch,
    pub warm_pool_size: usize,
    pub max_sandboxes: Option<usize>,
    pub max_rss_mb: Option<u64>,
    pub max_storage_mb: Option<u64>,
    pub admission_timeout_ms: u64,
}

impl ServeConfig {
    /// Converts daemon flags into a validated [`RuntimeManagerConfig`].
    pub fn to_runtime_config(&self) -> Result<RuntimeManagerConfig, SandboxError> {
        let warm_pool = if self.warm_pool_size > 0 {
            WarmPoolConfig {
                target_size: self.warm_pool_size,
                template_spec: Some(default_warm_template_spec()),
                ..WarmPoolConfig::default()
            }
        } else {
            WarmPoolConfig::default()
        };

        let cfg = RuntimeManagerConfig {
            state_dir: self.state_dir.clone(),
            max_copy_bytes: DEFAULT_MAX_COPY_BYTES,
            admission: AdmissionLimits {
                max_concurrent_sandboxes: self.max_sandboxes,
                max_total_host_rss_mb: self.max_rss_mb,
                max_total_host_storage_mb: self.max_storage_mb,
                admission_queue_timeout: Duration::from_millis(self.admission_timeout_ms),
                ..AdmissionLimits::default()
            },
            warm_pool,
            ..RuntimeManagerConfig::default()
        };
        cfg.validate()?;
        Ok(cfg)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum McpMode {
    Connected(ControlEndpoint),
    Standalone(Box<ServeConfig>),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct McpConfig {
    pub mode: McpMode,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Command {
    Help(&'static str),
    Serve(Box<ServeConfig>),
    Mcp(McpConfig),
}

/// Parses `std::env::args()` using process environment variables.
pub fn parse_env_args() -> Result<Command, SandboxError> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    parse_args_with(&args, |key| std::env::var(key).ok())
}

/// Parses `args` using an injectable environment lookup closure (pure and deterministic for tests).
pub fn parse_args_with<F>(args: &[String], get_env: F) -> Result<Command, SandboxError>
where
    F: Fn(&str) -> Option<String>,
{
    if args.is_empty() {
        return Err(SandboxError::InvalidSpec(
            "missing subcommand; expected 'serve' or 'mcp' (run with --help)".to_owned(),
        ));
    }

    let first = args[0].as_str();
    if matches!(first, "-h" | "--help" | "help") {
        return Ok(Command::Help(USAGE_TEXT));
    }
    if first == "--tcp" || first.starts_with("--tcp=") {
        return Err(plain_tcp_forbidden());
    }

    match first {
        "serve" => parse_serve_or_mcp_args(&args[1..], false, &get_env),
        "mcp" => parse_serve_or_mcp_args(&args[1..], true, &get_env),
        other => Err(SandboxError::InvalidSpec(format!(
            "unknown subcommand '{other}'; expected 'serve' or 'mcp' (run with --help)"
        ))),
    }
}

fn plain_tcp_forbidden() -> SandboxError {
    SandboxError::PolicyViolation(
        "plain TCP control listener without mTLS is forbidden; use owner-only Named Pipe or Unix socket".to_owned(),
    )
}

#[derive(Default)]
struct RawFlags {
    bundle_dir: Option<PathBuf>,
    pub_key_hex: Option<String>,
    pub_key_file: Option<PathBuf>,
    state_dir: Option<PathBuf>,
    endpoint: Option<String>,
    connect: Option<String>,
    ready_file: Option<PathBuf>,
    qemu_bin: Option<PathBuf>,
    qemu_img_bin: Option<PathBuf>,
    arch: Option<GuestArch>,
    warm_pool_size: Option<usize>,
    max_sandboxes: Option<usize>,
    max_rss_mb: Option<u64>,
    max_storage_mb: Option<u64>,
    admission_timeout_ms: Option<u64>,
}

fn parse_serve_or_mcp_args<F>(
    args: &[String],
    is_mcp: bool,
    get_env: &F,
) -> Result<Command, SandboxError>
where
    F: Fn(&str) -> Option<String>,
{
    let mut raw = RawFlags::default();
    let mut i = 0usize;

    while i < args.len() {
        let arg = args[i].as_str();
        if matches!(arg, "-h" | "--help") {
            return Ok(Command::Help(USAGE_TEXT));
        }
        if arg == "--tcp" || arg.starts_with("--tcp=") {
            return Err(plain_tcp_forbidden());
        }

        let (flag, inline_val) = split_flag(arg);
        let next_val = |idx: &mut usize, name: &str| -> Result<String, SandboxError> {
            if let Some(v) = inline_val {
                return Ok(v.to_owned());
            }
            *idx += 1;
            let Some(v) = args.get(*idx) else {
                return Err(SandboxError::InvalidSpec(format!(
                    "flag '{name}' requires a value"
                )));
            };
            Ok(v.clone())
        };

        match flag {
            "--bundle-dir" => raw.bundle_dir = Some(PathBuf::from(next_val(&mut i, flag)?)),
            "--pub-key-hex" => raw.pub_key_hex = Some(next_val(&mut i, flag)?),
            "--pub-key-file" => raw.pub_key_file = Some(PathBuf::from(next_val(&mut i, flag)?)),
            "--state-dir" => raw.state_dir = Some(PathBuf::from(next_val(&mut i, flag)?)),
            "--endpoint" => raw.endpoint = Some(next_val(&mut i, flag)?),
            "--connect" => {
                if !is_mcp {
                    return Err(SandboxError::InvalidSpec(
                        "--connect is only valid for 'sandboxd mcp'".to_owned(),
                    ));
                }
                raw.connect = Some(next_val(&mut i, flag)?);
            }
            "--ready-file" => {
                if is_mcp {
                    return Err(SandboxError::InvalidSpec(
                        "--ready-file is only valid for 'sandboxd serve'".to_owned(),
                    ));
                }
                raw.ready_file = Some(PathBuf::from(next_val(&mut i, flag)?));
            }
            "--qemu-bin" => raw.qemu_bin = Some(PathBuf::from(next_val(&mut i, flag)?)),
            "--qemu-img-bin" => raw.qemu_img_bin = Some(PathBuf::from(next_val(&mut i, flag)?)),
            "--arch" => raw.arch = Some(next_val(&mut i, flag)?.parse()?),
            "--warm-pool-size" => {
                raw.warm_pool_size = Some(parse_usize(&next_val(&mut i, flag)?, flag)?);
            }
            "--max-sandboxes" => {
                raw.max_sandboxes = Some(parse_usize(&next_val(&mut i, flag)?, flag)?);
            }
            "--max-rss-mb" => {
                raw.max_rss_mb = Some(parse_u64(&next_val(&mut i, flag)?, flag)?);
            }
            "--max-storage-mb" => {
                raw.max_storage_mb = Some(parse_u64(&next_val(&mut i, flag)?, flag)?);
            }
            "--admission-timeout-ms" => {
                raw.admission_timeout_ms = Some(parse_u64(&next_val(&mut i, flag)?, flag)?);
            }
            other => {
                return Err(SandboxError::InvalidSpec(format!(
                    "unknown option '{other}'"
                )));
            }
        }
        i += 1;
    }

    if is_mcp {
        if let Some(connect_raw) = raw.connect.as_deref() {
            if raw.bundle_dir.is_some()
                || raw.pub_key_hex.is_some()
                || raw.pub_key_file.is_some()
                || raw.state_dir.is_some()
                || raw.endpoint.is_some()
                || raw.qemu_bin.is_some()
                || raw.qemu_img_bin.is_some()
                || raw.arch.is_some()
                || raw.warm_pool_size.is_some()
                || raw.max_sandboxes.is_some()
                || raw.max_rss_mb.is_some()
                || raw.max_storage_mb.is_some()
                || raw.admission_timeout_ms.is_some()
            {
                return Err(SandboxError::InvalidSpec(
                    "cannot combine '--connect' with standalone serve options".to_owned(),
                ));
            }
            let endpoint = ControlEndpoint::parse(connect_raw)?;
            return Ok(Command::Mcp(McpConfig {
                mode: McpMode::Connected(endpoint),
            }));
        }
    }

    let serve_cfg = build_serve_config(raw, is_mcp, get_env)?;
    if is_mcp {
        Ok(Command::Mcp(McpConfig {
            mode: McpMode::Standalone(Box::new(serve_cfg)),
        }))
    } else {
        Ok(Command::Serve(Box::new(serve_cfg)))
    }
}

fn build_serve_config<F>(
    raw: RawFlags,
    is_mcp: bool,
    get_env: &F,
) -> Result<ServeConfig, SandboxError>
where
    F: Fn(&str) -> Option<String>,
{
    let bundle_dir = raw
        .bundle_dir
        .or_else(|| non_empty_env(get_env, "MINIPOD_BUNDLE_DIR").map(PathBuf::from))
        .ok_or_else(|| {
            if is_mcp {
                SandboxError::InvalidSpec(
                    "sandboxd mcp requires either '--connect <endpoint>' or '--bundle-dir <path>' (env: MINIPOD_BUNDLE_DIR)"
                        .to_owned(),
                )
            } else {
                SandboxError::InvalidSpec(
                    "--bundle-dir <path> is required (or set MINIPOD_BUNDLE_DIR)".to_owned(),
                )
            }
        })?;
    if bundle_dir.as_os_str().is_empty() {
        return Err(SandboxError::InvalidSpec(
            "--bundle-dir cannot be empty".to_owned(),
        ));
    }

    let pub_key = match (raw.pub_key_hex, raw.pub_key_file) {
        (Some(_), Some(_)) => {
            return Err(SandboxError::InvalidSpec(
                "cannot specify both --pub-key-hex and --pub-key-file".to_owned(),
            ));
        }
        (Some(hex), None) => {
            let key = decode_hex_exact::<32>(hex.trim())?;
            let _ = BundleVerifier::with_public_key(key)?;
            PubKeySource::Hex(hex)
        }
        (None, Some(path)) => {
            if path.as_os_str().is_empty() {
                return Err(SandboxError::InvalidSpec(
                    "--pub-key-file cannot be empty".to_owned(),
                ));
            }
            PubKeySource::File(path)
        }
        (None, None) => {
            let env_hex = non_empty_env(get_env, "MINIPOD_PUB_KEY_HEX");
            let env_file = non_empty_env(get_env, "MINIPOD_PUB_KEY_FILE");
            match (env_hex, env_file) {
                (Some(_), Some(_)) => {
                    return Err(SandboxError::InvalidSpec(
                        "cannot set both MINIPOD_PUB_KEY_HEX and MINIPOD_PUB_KEY_FILE".to_owned(),
                    ));
                }
                (Some(hex), None) => {
                    let key = decode_hex_exact::<32>(hex.trim())?;
                    let _ = BundleVerifier::with_public_key(key)?;
                    PubKeySource::Hex(hex)
                }
                (None, Some(path)) => PubKeySource::File(PathBuf::from(path)),
                (None, None) => PubKeySource::Embedded,
            }
        }
    };

    let state_dir = raw
        .state_dir
        .or_else(|| non_empty_env(get_env, "MINIPOD_STATE_DIR").map(PathBuf::from))
        .unwrap_or_else(|| default_state_dir(get_env));
    if state_dir.as_os_str().is_empty() {
        return Err(SandboxError::InvalidSpec(
            "--state-dir cannot be empty".to_owned(),
        ));
    }

    let endpoint = match raw.endpoint {
        Some(ep) => ControlEndpoint::parse(&ep)?,
        None => default_control_endpoint_with(get_env)?,
    };

    let qemu_bin = raw
        .qemu_bin
        .or_else(|| non_empty_env(get_env, "MINIPOD_QEMU_BIN").map(PathBuf::from));
    let qemu_img_bin = raw
        .qemu_img_bin
        .or_else(|| non_empty_env(get_env, "MINIPOD_QEMU_IMG_BIN").map(PathBuf::from));
    let arch = match raw.arch {
        Some(a) => a,
        None => match non_empty_env(get_env, "MINIPOD_ARCH") {
            Some(val) => val.parse()?,
            None => GuestArch::host_native().unwrap_or(GuestArch::X86_64),
        },
    };

    let cfg = ServeConfig {
        bundle_dir,
        pub_key,
        state_dir,
        endpoint,
        ready_file: raw.ready_file,
        qemu_bin,
        qemu_img_bin,
        arch,
        warm_pool_size: raw.warm_pool_size.unwrap_or(0),
        max_sandboxes: raw.max_sandboxes,
        max_rss_mb: raw.max_rss_mb,
        max_storage_mb: raw.max_storage_mb,
        admission_timeout_ms: raw.admission_timeout_ms.unwrap_or(0),
    };
    cfg.to_runtime_config()?;
    Ok(cfg)
}

/// Computes the platform owner-local default [`ControlEndpoint`] using the provided env lookup.
pub fn default_control_endpoint_with<F>(get_env: &F) -> Result<ControlEndpoint, SandboxError>
where
    F: Fn(&str) -> Option<String>,
{
    if let Some(ep) = non_empty_env(get_env, "MINIPOD_ENDPOINT") {
        return ControlEndpoint::parse(&ep);
    }

    #[cfg(windows)]
    {
        let sanitized = non_empty_env(get_env, "USERNAME")
            .map(|u| sanitize_pipe_suffix(&u))
            .unwrap_or_default();
        let pipe_name = if sanitized.is_empty() {
            "minipod-sandboxd".to_owned()
        } else {
            format!("minipod-sandboxd-{sanitized}")
        };
        ControlEndpoint::parse(&format!(r"\\.\pipe\{pipe_name}"))
    }

    #[cfg(unix)]
    {
        const MAX_UNIX_SOCK_BYTES: usize = 103;
        if let Some(xdg) = non_empty_env(get_env, "XDG_RUNTIME_DIR") {
            let candidate = PathBuf::from(xdg).join("minipod").join("ctl.sock");
            if is_valid_short_unix_socket(&candidate, MAX_UNIX_SOCK_BYTES) {
                return Ok(ControlEndpoint::UnixSocket(candidate));
            }
        }

        let uid = current_unix_uid()?;
        let temp_candidate = std::env::temp_dir()
            .join(format!("minipod-{uid}"))
            .join("ctl.sock");
        if is_valid_short_unix_socket(&temp_candidate, MAX_UNIX_SOCK_BYTES) {
            return Ok(ControlEndpoint::UnixSocket(temp_candidate));
        }

        let fallback = PathBuf::from(format!("/tmp/minipod-{uid}/ctl.sock"));
        Ok(ControlEndpoint::UnixSocket(fallback))
    }
}

#[cfg(windows)]
fn sanitize_pipe_suffix(raw: &str) -> String {
    raw.chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        .take(48)
        .collect::<String>()
        .trim_matches('.')
        .to_owned()
}

#[cfg(unix)]
fn is_valid_short_unix_socket(path: &std::path::Path, max_bytes: usize) -> bool {
    path.to_str().is_some_and(|s| {
        !s.is_empty()
            && s.len() <= max_bytes
            && !s.contains('\0')
            && !s.contains(',')
            && !s.contains("..")
    })
}

#[cfg(unix)]
pub(crate) fn current_unix_uid() -> Result<u32, SandboxError> {
    use std::fs::{self, OpenOptions};
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    use std::sync::atomic::{AtomicU64, Ordering};

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
        let probe_path = tmp_dir.join(format!("mp-uid-{}-{seq}", std::process::id()));
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
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
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

fn default_state_dir<F>(get_env: &F) -> PathBuf
where
    F: Fn(&str) -> Option<String>,
{
    #[cfg(windows)]
    {
        if let Some(local_app_data) = non_empty_env(get_env, "LOCALAPPDATA") {
            return PathBuf::from(local_app_data).join("minipod").join("state");
        }
        std::env::temp_dir().join("minipod-state")
    }
    #[cfg(unix)]
    {
        if let Some(xdg_state) = non_empty_env(get_env, "XDG_STATE_HOME") {
            return PathBuf::from(xdg_state).join("minipod");
        }
        if let Some(home) = non_empty_env(get_env, "HOME") {
            return PathBuf::from(home)
                .join(".local")
                .join("state")
                .join("minipod");
        }
        let uid = current_unix_uid().unwrap_or_else(|_| std::process::id());
        std::env::temp_dir().join(format!("minipod-state-{uid}"))
    }
}

fn default_warm_template_spec() -> SandboxSpec {
    SandboxSpec {
        isolation: IsolationMode::VmRequired,
        acceleration: AccelerationPolicy::Preferred,
        network: NetworkPolicy::Isolated,
        budget: ResourceBudget {
            guest_vcpus: 1,
            host_cpu_quota_Millicores: None,
            guest_ram_mb: 256,
            host_rss_budget_mb: Some(512),
            virtual_disk_mb: 512,
            host_storage_budget_mb: 1024,
        },
        lease_ttl: Duration::from_secs(300),
    }
}

fn non_empty_env<F>(get_env: &F, key: &str) -> Option<String>
where
    F: Fn(&str) -> Option<String>,
{
    get_env(key).and_then(|v| {
        let trimmed = v.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_owned())
        }
    })
}

fn split_flag(arg: &str) -> (&str, Option<&str>) {
    if arg.starts_with("--") {
        if let Some((k, v)) = arg.split_once('=') {
            return (k, Some(v));
        }
    }
    (arg, None)
}

fn parse_usize(raw: &str, flag: &str) -> Result<usize, SandboxError> {
    raw.parse::<usize>().map_err(|err| {
        SandboxError::InvalidSpec(format!("invalid integer '{raw}' for {flag}: {err}"))
    })
}

fn parse_u64(raw: &str, flag: &str) -> Result<u64, SandboxError> {
    raw.parse::<u64>().map_err(|err| {
        SandboxError::InvalidSpec(format!("invalid integer '{raw}' for {flag}: {err}"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn args(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| (*s).to_owned()).collect()
    }

    fn no_env(_key: &str) -> Option<String> {
        None
    }

    #[test]
    fn help_and_tcp_rejection_work_across_subcommands() {
        assert!(matches!(
            parse_args_with(&args(&["--help"]), no_env),
            Ok(Command::Help(_))
        ));
        assert!(matches!(
            parse_args_with(&args(&["serve", "-h"]), no_env),
            Ok(Command::Help(_))
        ));
        assert!(matches!(
            parse_args_with(&args(&["mcp", "--help"]), no_env),
            Ok(Command::Help(_))
        ));

        for tcp_args in [
            args(&["serve", "--bundle-dir", "/b", "--tcp", "127.0.0.1:9000"]),
            args(&["serve", "--bundle-dir", "/b", "--tcp=0.0.0.0:9000"]),
            args(&["mcp", "--tcp", "127.0.0.1:9000"]),
            args(&["--tcp", "127.0.0.1:9000"]),
            args(&["serve", "--bundle-dir", "/b", "--endpoint", "tcp://127.0.0.1:9000"]),
            args(&["mcp", "--connect", "tcp://127.0.0.1:9000"]),
        ] {
            assert!(
                matches!(
                    parse_args_with(&tcp_args, no_env),
                    Err(SandboxError::PolicyViolation(_))
                ),
                "expected PolicyViolation for {tcp_args:?}"
            );
        }
    }

    #[test]
    fn serve_parses_all_options_and_validates_pub_key_and_zero_limits() {
        let valid_hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        // Verify a real non-weak Ed25519 key (generated via public_key_from_secret).
        let pub_bytes = sandbox_image::public_key_from_secret(&[0x42u8; 32]);
        let pub_hex = sandbox_image::encode_hex(&pub_bytes);

        let ep = if cfg!(windows) {
            r"\\.\pipe\minipod-test-ctl"
        } else {
            "unix:///tmp/mp-test/ctl.sock"
        };

        let cmd = parse_args_with(
            &args(&[
                "serve",
                "--bundle-dir",
                "bundles/x86_64",
                "--pub-key-hex",
                &pub_hex,
                "--state-dir",
                "state-dir",
                "--endpoint",
                ep,
                "--ready-file",
                "ready.json",
                "--qemu-bin",
                "/usr/bin/qemu",
                "--qemu-img-bin",
                "/usr/bin/qemu-img",
                "--arch",
                "aarch64",
                "--warm-pool-size",
                "2",
                "--max-sandboxes",
                "4",
                "--max-rss-mb",
                "2048",
                "--max-storage-mb",
                "4096",
                "--admission-timeout-ms",
                "1500",
            ]),
            no_env,
        )
        .unwrap();

        let Command::Serve(cfg) = cmd else {
            panic!("expected Serve command");
        };
        let cfg = *cfg;
        assert_eq!(cfg.bundle_dir, PathBuf::from("bundles/x86_64"));
        assert_eq!(cfg.pub_key, PubKeySource::Hex(pub_hex));
        assert_eq!(cfg.state_dir, PathBuf::from("state-dir"));
        assert_eq!(cfg.ready_file, Some(PathBuf::from("ready.json")));
        assert_eq!(cfg.qemu_bin, Some(PathBuf::from("/usr/bin/qemu")));
        assert_eq!(cfg.qemu_img_bin, Some(PathBuf::from("/usr/bin/qemu-img")));
        assert_eq!(cfg.arch, GuestArch::Aarch64);
        assert_eq!(cfg.warm_pool_size, 2);
        assert_eq!(cfg.max_sandboxes, Some(4));
        assert_eq!(cfg.max_rss_mb, Some(2048));
        assert_eq!(cfg.max_storage_mb, Some(4096));
        assert_eq!(cfg.admission_timeout_ms, 1500);

        let rt_cfg = cfg.to_runtime_config().unwrap();
        assert_eq!(rt_cfg.warm_pool.target_size, 2);
        assert!(rt_cfg.warm_pool.template_spec.is_some());
        assert_eq!(rt_cfg.admission.max_concurrent_sandboxes, Some(4));
        assert_eq!(
            rt_cfg.admission.admission_queue_timeout,
            Duration::from_millis(1500)
        );

        // Mutually exclusive pub-key flags rejected.
        assert!(matches!(
            parse_args_with(
                &args(&[
                    "serve",
                    "--bundle-dir",
                    "b",
                    "--pub-key-hex",
                    valid_hex,
                    "--pub-key-file",
                    "k.pub",
                ]),
                no_env
            ),
            Err(SandboxError::InvalidSpec(_))
        ));

        // Zero admission ceiling rejected cleanly.
        assert!(matches!(
            parse_args_with(
                &args(&["serve", "--bundle-dir", "b", "--max-sandboxes", "0"]),
                no_env
            ),
            Err(SandboxError::InvalidSpec(_))
        ));
    }

    #[test]
    fn mcp_parses_connected_and_standalone_modes_and_rejects_mixed_flags() {
        let ep = if cfg!(windows) {
            "npipe://minipod-mcp-test"
        } else {
            "unix:///tmp/mp-mcp.sock"
        };
        let connected = parse_args_with(&args(&["mcp", "--connect", ep]), no_env).unwrap();
        assert!(matches!(
            connected,
            Command::Mcp(McpConfig {
                mode: McpMode::Connected(_)
            })
        ));

        let standalone = parse_args_with(
            &args(&["mcp", "--bundle-dir", "bundle", "--warm-pool-size", "1"]),
            no_env,
        )
        .unwrap();
        assert!(matches!(
            standalone,
            Command::Mcp(McpConfig {
                mode: McpMode::Standalone(ref s)
            }) if s.warm_pool_size == 1 && s.pub_key == PubKeySource::Embedded
        ));

        assert!(matches!(
            parse_args_with(
                &args(&["mcp", "--connect", ep, "--bundle-dir", "bundle"]),
                no_env
            ),
            Err(SandboxError::InvalidSpec(_))
        ));
        assert!(matches!(
            parse_args_with(&args(&["mcp"]), no_env),
            Err(SandboxError::InvalidSpec(_))
        ));
    }

    #[test]
    fn default_endpoint_respects_env_and_platform_bounds() {
        let mut env_map = HashMap::new();
        if cfg!(windows) {
            env_map.insert("USERNAME", "Alice\\Bad/Name!".to_owned());
            let ep = default_control_endpoint_with(&|k| env_map.get(k).cloned()).unwrap();
            assert_eq!(
                ep,
                ControlEndpoint::NamedPipe(r"\\.\pipe\minipod-sandboxd-AliceBadName".to_owned())
            );
        } else {
            env_map.insert("XDG_RUNTIME_DIR", "/run/user/1000".to_owned());
            let ep = default_control_endpoint_with(&|k| env_map.get(k).cloned()).unwrap();
            assert_eq!(
                ep,
                ControlEndpoint::UnixSocket(PathBuf::from("/run/user/1000/minipod/ctl.sock"))
            );

            // Fallback when XDG_RUNTIME_DIR is absent must still stay <= 103 bytes.
            let fallback = default_control_endpoint_with(&no_env).unwrap();
            let ControlEndpoint::UnixSocket(path) = fallback else {
                panic!("expected UnixSocket");
            };
            assert!(path.to_str().unwrap().len() <= 103);
        }
    }

    #[test]
    fn to_runtime_config_aligns_copy_budget_and_pubkey_file_rejects_symlinks_and_oversize() {
        let Command::Serve(serve_cfg) = parse_args_with(
            &args(&["serve", "--bundle-dir", "bundle", "--state-dir", "state"]),
            no_env,
        )
        .unwrap() else {
            panic!("expected Command::Serve");
        };
        let rt_cfg = serve_cfg.to_runtime_config().unwrap();
        assert_eq!(rt_cfg.max_copy_bytes, DEFAULT_MAX_COPY_BYTES);

        let dir = std::env::temp_dir().join(format!(
            "mp-cfg-key-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let big_file = dir.join("big.pub");
        std::fs::write(&big_file, vec![b'a'; (MAX_PUB_KEY_FILE_BYTES + 1) as usize]).unwrap();
        assert!(matches!(
            PubKeySource::File(big_file).load_verifier(),
            Err(SandboxError::InvalidSpec(_))
        ));

        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            let real = dir.join("real.pub");
            std::fs::write(&real, "00".repeat(32)).unwrap();
            let sym = dir.join("sym.pub");
            symlink(&real, &sym).unwrap();
            assert!(matches!(
                PubKeySource::File(sym).load_verifier(),
                Err(SandboxError::PolicyViolation(_))
            ));
        }

        let _ = std::fs::remove_dir_all(&dir);
    }
}
