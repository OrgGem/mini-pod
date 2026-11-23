//! Security policy gate and port normalization for Docker `POST /containers/create` payloads.

use std::collections::BTreeSet;
use std::fmt;

use serde_json::{json, Map, Value};

const DOCKER_SOCKET_PATH: &str = "/var/run/docker.sock";
const DOCKER_SOCKET_WIN_PREFIX_PATH: &str = "//var/run/docker.sock";
const GUEST_PODMAN_SOCKET_PATH: &str = "/run/podman/podman.sock";
const DEFAULT_CONTAINER_NO_PROXY: &str = "localhost,127.0.0.1,::1,10.88.0.1";
const MAX_JSON_NESTING_DEPTH: usize = 128;

const KNOWN_ROOT_FIELDS: &[&str] = &[
    "Volumes",
    "ExposedPorts",
    "HostConfig",
    "NetworkingConfig",
    "Env",
];
const KNOWN_NETWORKING_CONFIG_FIELDS: &[&str] = &["EndpointsConfig"];
const KNOWN_HOST_CONFIG_FIELDS: &[&str] = &[
    "Privileged",
    "PidMode",
    "NetworkMode",
    "IpcMode",
    "UsernsMode",
    "UTSMode",
    "CgroupnsMode",
    "Binds",
    "Mounts",
    "VolumesFrom",
    "PortBindings",
    "PublishAllPorts",
    "CapAdd",
    "Devices",
    "DeviceCgroupRules",
    "DeviceRequests",
    "SecurityOpt",
    "MaskedPaths",
    "ReadonlyPaths",
    "Annotations",
    "VolumeDriver",
    "CgroupParent",
    "Cgroup",
    "Runtime",
    "Sysctls",
    "ContainerIDFile",
    "LogConfig",
    "OomKillDisable",
    "OomScoreAdj",
    "StorageOpt",
    "Tmpfs",
];
const KNOWN_LOG_CONFIG_FIELDS: &[&str] = &["Type", "Config"];
const KNOWN_MOUNT_FIELDS: &[&str] = &[
    "Type",
    "Source",
    "Target",
    "Destination",
    "VolumeOptions",
    "BindOptions",
    "TmpfsOptions",
    "ReadOnly",
];
const KNOWN_TMPFS_OPTIONS_FIELDS: &[&str] = &["SizeBytes", "Mode", "Options"];
const KNOWN_VOLUME_OPTIONS_FIELDS: &[&str] = &["NoCopy", "Labels", "DriverConfig", "Subpath"];
const KNOWN_DRIVER_CONFIG_FIELDS: &[&str] = &["Name", "Options"];
const KNOWN_PORT_BINDING_FIELDS: &[&str] = &["HostIp", "HostPort"];
const KNOWN_VOLUME_CREATE_FIELDS: &[&str] = &[
    "Name",
    "Driver",
    "DriverOpts",
    "Labels",
    "ClusterVolumeSpec",
];
const KNOWN_EXEC_CREATE_FIELDS: &[&str] = &[
    "AttachStdin",
    "AttachStdout",
    "AttachStderr",
    "DetachKeys",
    "Tty",
    "Env",
    "Cmd",
    "Privileged",
    "User",
    "WorkingDir",
    "ConsoleSize",
];
const KNOWN_NETWORK_CREATE_FIELDS: &[&str] = &[
    "Name",
    "CheckDuplicate",
    "Driver",
    "Scope",
    "Internal",
    "Attachable",
    "Ingress",
    "IPAM",
    "EnableIPv6",
    "Options",
    "Labels",
    "ConfigOnly",
    "ConfigFrom",
];
const KNOWN_NETWORK_CONNECT_FIELDS: &[&str] = &["Container", "EndpointConfig"];

/// Controls whether a container's request to mount `/var/run/docker.sock` (e.g., Testcontainers
/// Ryuk reaper) is rejected or rewritten to the guest VM's internal Podman Unix socket.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ReaperSocketPolicy {
    #[default]
    Deny,
    MapGuestPodmanSocket,
}

/// Security policy applied by the Docker API compatibility adapter on container creation.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DockerCompatPolicy {
    pub reaper_socket: ReaperSocketPolicy,
    pub container_proxy_http_url: Option<String>,
}

/// Host-to-container TCP port binding requested by a Docker client before VM-side normalization.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequestedPortBinding {
    pub container_port: u16,
    pub protocol: String,
    pub host_port: Option<u16>,
    pub container_key: String,
}

/// Sanitized container-create payload and extracted Host port bindings ready to forward to Podman.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SanitizedCreatePlan {
    pub rewritten_body: Vec<u8>,
    pub requested_ports: Vec<RequestedPortBinding>,
}

/// Error returned when a Docker API request violates isolation or host-boundary policy (HTTP 400).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyRejection {
    pub reason: String,
}

impl PolicyRejection {
    pub fn new(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
        }
    }

    pub fn reason(&self) -> &str {
        &self.reason
    }
}

impl fmt::Display for PolicyRejection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.reason)
    }
}

impl std::error::Error for PolicyRejection {}

/// Validates query parameters on Docker `POST /images/create`.
///
/// Rejects unallowlisted query keys, local archive transports, non-URL paths or non-public/SSRF
/// destinations in `fromSrc`, invalid tags/platforms, unsafe control characters, and non-ASCII keys.
pub fn validate_image_create_query(params: &[(String, String)]) -> Result<(), PolicyRejection> {
    for (raw_key, val) in params {
        if !raw_key.is_ascii()
            || raw_key.bytes().any(|b| b < 0x20 || b == 0x7f)
            || val
                .bytes()
                .any(|b| b == 0x7f || (b < 0x20 && !matches!(b, b'\t' | b'\n' | b'\r')))
        {
            return Err(PolicyRejection::new(format!(
                "invalid control or non-ASCII characters in POST /images/create parameter '{raw_key}'"
            )));
        }

        let key = raw_key.to_ascii_lowercase();
        match key.as_str() {
            "fromsrc" => validate_image_create_from_src(val)?,
            "fromimage" => validate_image_create_from_image(val, "fromImage")?,
            "repo" => validate_image_create_from_image(val, "repo")?,
            "tag" => validate_image_create_tag(val)?,
            "quiet" => {
                if !val.is_empty()
                    && !val.eq_ignore_ascii_case("true")
                    && !val.eq_ignore_ascii_case("false")
                    && val != "1"
                    && val != "0"
                {
                    return Err(PolicyRejection::new(format!(
                        "POST /images/create quiet '{val}' must be a boolean"
                    )));
                }
            }
            "message" | "changes" => {}
            "platform" => validate_image_create_platform(val)?,
            _ => {
                return Err(PolicyRejection::new(format!(
                    "POST /images/create parameter '{raw_key}' is forbidden by security policy"
                )));
            }
        }
    }
    Ok(())
}

fn validate_image_create_from_src(val: &str) -> Result<(), PolicyRejection> {
    if val.is_empty() || val == "-" {
        return Ok(());
    }
    if val.bytes().any(|b| b.is_ascii_whitespace()) {
        return Err(PolicyRejection::new(format!(
            "POST /images/create fromSrc '{val}' must not contain whitespace"
        )));
    }
    let rest = if val.len() >= "http://".len() && val[.."http://".len()].eq_ignore_ascii_case("http://") {
        &val["http://".len()..]
    } else if val.len() >= "https://".len() && val[.."https://".len()].eq_ignore_ascii_case("https://") {
        &val["https://".len()..]
    } else {
        return Err(PolicyRejection::new(format!(
            "POST /images/create fromSrc '{val}' must be '-' or a public http(s) URL"
        )));
    };

    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    if authority.is_empty() || authority.contains('@') {
        return Err(PolicyRejection::new(format!(
            "POST /images/create fromSrc '{val}' has an invalid authority"
        )));
    }

    if authority.starts_with('[') {
        let Some(end) = authority.find(']') else {
            return Err(PolicyRejection::new(format!(
                "POST /images/create fromSrc '{val}' has an invalid IPv6 host"
            )));
        };
        let suffix = &authority[end + 1..];
        if !suffix.is_empty()
            && suffix
                .strip_prefix(':')
                .is_none_or(|p| p.is_empty() || p.parse::<u16>().is_err())
        {
            return Err(PolicyRejection::new(format!(
                "POST /images/create fromSrc '{val}' has an invalid host port"
            )));
        }
        let ipv6_raw = &authority[1..end];
        let v6 = ipv6_raw.parse::<std::net::Ipv6Addr>().map_err(|_| {
            PolicyRejection::new(format!(
                "POST /images/create fromSrc '{val}' has an invalid bracketed IPv6 literal"
            ))
        })?;
        if sandbox_runtime::is_forbidden_ip(std::net::IpAddr::V6(v6)) {
            return Err(PolicyRejection::new(format!(
                "POST /images/create fromSrc '{val}' targets a non-public IP address"
            )));
        }
        return Ok(());
    }

    if authority.contains(']') {
        return Err(PolicyRejection::new(format!(
            "POST /images/create fromSrc '{val}' has an invalid authority"
        )));
    }
    let mut parts = authority.split(':');
    let host = parts.next().unwrap_or("");
    if let Some(port) = parts.next() {
        if parts.next().is_some() || port.is_empty() || port.parse::<u16>().is_err() {
            return Err(PolicyRejection::new(format!(
                "POST /images/create fromSrc '{val}' has an invalid host port"
            )));
        }
    }

    let host_trimmed = host.trim_end_matches('.');
    if host_trimmed.is_empty() || host_trimmed.contains('%') {
        return Err(PolicyRejection::new(format!(
            "POST /images/create fromSrc '{val}' targets a forbidden local/internal host"
        )));
    }

    if let Ok(ip) = host_trimmed.parse::<std::net::IpAddr>() {
        if sandbox_runtime::is_forbidden_ip(ip) {
            return Err(PolicyRejection::new(format!(
                "POST /images/create fromSrc '{val}' targets a non-public IP address"
            )));
        }
        return Ok(());
    }

    let normalized = sandbox_core::normalize_egress_domain(host_trimmed).map_err(|err| {
        PolicyRejection::new(format!("POST /images/create fromSrc '{val}' invalid host: {err}"))
    })?;
    if normalized.contains('*')
        || !normalized.contains('.')
        || normalized == "localhost"
        || normalized.ends_with(".localhost")
        || normalized.ends_with(".local")
        || normalized.ends_with(".internal")
        || normalized.ends_with(".localdomain")
        || matches!(normalized.as_str(), "ip6-localhost" | "ip6-loopback")
    {
        return Err(PolicyRejection::new(format!(
            "POST /images/create fromSrc '{val}' targets a forbidden local/internal host"
        )));
    }

    let labels: Vec<&str> = normalized.split('.').collect();
    let tld = labels.last().copied().unwrap_or("");
    let is_numeric_or_hex_label = |label: &str| {
        !label.is_empty()
            && (label.bytes().all(|b| b.is_ascii_digit())
                || (label.starts_with("0x")
                    && label.len() > 2
                    && label[2..].bytes().all(|b| b.is_ascii_hexdigit())))
    };
    if is_numeric_or_hex_label(tld) || labels.iter().all(|l| is_numeric_or_hex_label(l)) {
        return Err(PolicyRejection::new(format!(
            "POST /images/create fromSrc '{val}' uses a disallowed non-canonical numeric/hex host"
        )));
    }

    Ok(())
}

fn validate_image_create_from_image(val: &str, label: &str) -> Result<(), PolicyRejection> {
    if val.is_empty() {
        return Ok(());
    }
    if val.bytes().any(|b| b.is_ascii_whitespace()) {
        return Err(PolicyRejection::new(format!(
            "POST /images/create {label} '{val}' must not contain whitespace"
        )));
    }
    if val.starts_with('/') || val.starts_with('\\') || val.contains('\\') || val.contains("..") {
        return Err(PolicyRejection::new(format!(
            "POST /images/create {label} '{val}' contains a forbidden filesystem path"
        )));
    }
    let lower = val.to_ascii_lowercase();
    if lower.contains("://") && !lower.starts_with("docker://") {
        return Err(PolicyRejection::new(format!(
            "POST /images/create {label} '{val}' uses a forbidden URL scheme"
        )));
    }
    let check_target = lower.strip_prefix("docker://").unwrap_or(&lower);
    if check_target.is_empty() {
        return Err(PolicyRejection::new(format!(
            "POST /images/create {label} '{val}' cannot have an empty registry reference"
        )));
    }
    let head = check_target.split('/').next().unwrap_or("");
    for transport in [
        "dir:",
        "oci:",
        "oci-archive:",
        "docker-archive:",
        "docker-daemon:",
        "containers-storage:",
        "ostree:",
        "sif:",
        "file:",
        "http:",
        "https:",
        "tarball:",
        "atomic:",
    ] {
        if head.starts_with(transport) {
            return Err(PolicyRejection::new(format!(
                "POST /images/create {label} '{val}' uses forbidden local/non-registry transport '{transport}'"
            )));
        }
    }
    if check_target.contains('/') && head.contains(':') && !is_valid_registry_head(head) {
        return Err(PolicyRejection::new(format!(
            "POST /images/create {label} '{val}' contains an invalid registry host:port or unknown transport"
        )));
    }
    Ok(())
}

fn is_valid_registry_head(head: &str) -> bool {
    if let Some(after_open) = head.strip_prefix('[') {
        let Some((ip_str, rest)) = after_open.split_once(']') else {
            return false;
        };
        if ip_str.parse::<std::net::Ipv6Addr>().is_err() {
            return false;
        }
        if rest.is_empty() {
            return true;
        }
        let Some(port_str) = rest.strip_prefix(':') else {
            return false;
        };
        return !port_str.is_empty()
            && port_str.bytes().all(|b| b.is_ascii_digit())
            && matches!(port_str.parse::<u16>(), Ok(p) if p > 0);
    }
    let Some((host, port_str)) = head.split_once(':') else {
        return false;
    };
    !host.is_empty()
        && !host.contains([':', '[', ']'])
        && !port_str.is_empty()
        && port_str.bytes().all(|b| b.is_ascii_digit())
        && matches!(port_str.parse::<u16>(), Ok(p) if p > 0)
}

fn validate_image_create_tag(val: &str) -> Result<(), PolicyRejection> {
    if val.is_empty() {
        return Ok(());
    }
    if val.bytes().any(|b| b.is_ascii_whitespace()) {
        return Err(PolicyRejection::new(format!(
            "POST /images/create tag '{val}' must not contain whitespace"
        )));
    }
    if let Some(hex) = val.strip_prefix("sha256:") {
        if hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Ok(());
        }
        return Err(PolicyRejection::new(format!(
            "POST /images/create tag '{val}' has an invalid sha256 digest"
        )));
    }
    let valid = val.len() <= 128
        && !val.contains("..")
        && val.bytes().enumerate().all(|(idx, b)| {
            if idx == 0 {
                b.is_ascii_alphanumeric() || b == b'_'
            } else {
                b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-')
            }
        });
    if !valid {
        return Err(PolicyRejection::new(format!(
            "POST /images/create tag '{val}' contains forbidden characters"
        )));
    }
    Ok(())
}

fn validate_image_create_platform(val: &str) -> Result<(), PolicyRejection> {
    if val.is_empty() {
        return Ok(());
    }
    if val.bytes().any(|b| b.is_ascii_whitespace())
        || val.contains('\\')
        || val.contains("..")
        || val.contains(':')
        || val.starts_with('/')
        || val.ends_with('/')
    {
        return Err(PolicyRejection::new(format!(
            "POST /images/create platform '{val}' is invalid"
        )));
    }
    Ok(())
}

/// Validates and rewrites a Docker `POST /containers/create` JSON body under `policy`.
///
/// Rejects privileged execution, host namespace sharing, raw host bind mounts, unsafe top-level
/// `Volumes` keys, non-TCP published ports, and non-loopback `HostIp` bindings. Rewrites valid
/// published ports to loopback ephemeral guest allocations (`127.0.0.1:""`) and optionally maps
/// the Testcontainers Ryuk socket bind to `/run/podman/podman.sock`.
pub fn sanitize_container_create(
    body: &[u8],
    policy: &DockerCompatPolicy,
) -> Result<SanitizedCreatePlan, PolicyRejection> {
    let mut root: Value = serde_json::from_slice(body)
        .map_err(|err| PolicyRejection::new(format!("invalid container create JSON: {err}")))?;
    reject_duplicate_json_keys(body)?;
    let root_obj = root
        .as_object_mut()
        .ok_or_else(|| PolicyRejection::new("container create body must be a JSON object"))?;
    canonicalize_struct_keys(root_obj, KNOWN_ROOT_FIELDS, "CreateContainer")?;

    if let Some(volumes) = root_obj.get("Volumes") {
        validate_top_level_volumes(volumes)?;
    }

    if let Some(net_cfg) = root_obj.get_mut("NetworkingConfig") {
        validate_networking_config(net_cfg)?;
    }

    let exposed_tcp_ports = match root_obj.get("ExposedPorts") {
        Some(exposed) => collect_exposed_tcp_ports(exposed)?,
        None => Vec::new(),
    };

    let mut requested_ports = Vec::new();
    if let Some(host_cfg) = root_obj.get_mut("HostConfig") {
        if !host_cfg.is_null() {
            let hc = host_cfg.as_object_mut().ok_or_else(|| {
                PolicyRejection::new("HostConfig must be a JSON object when provided")
            })?;
            canonicalize_struct_keys(hc, KNOWN_HOST_CONFIG_FIELDS, "HostConfig")?;
            validate_host_config_security(hc, policy)?;
            requested_ports = normalize_host_config_ports(hc, &exposed_tcp_ports)?;
        }
    }

    if let Some(proxy_url) = policy.container_proxy_http_url.as_deref() {
        inject_container_proxy_env(root_obj, proxy_url)?;
    }

    let rewritten_body = serde_json::to_vec(&root).map_err(|err| {
        PolicyRejection::new(format!("failed to serialize sanitized JSON: {err}"))
    })?;

    Ok(SanitizedCreatePlan {
        rewritten_body,
        requested_ports,
    })
}

/// Validates and rewrites a Docker `POST /volumes/create` JSON body, blocking host bind options
/// (`DriverOpts` `device`/`o`/`type` or host paths) and non-`local` volume drivers.
pub fn sanitize_volume_create(body: &[u8]) -> Result<Vec<u8>, PolicyRejection> {
    if body.iter().all(u8::is_ascii_whitespace) {
        return Ok(b"{}".to_vec());
    }
    let mut root: Value = serde_json::from_slice(body)
        .map_err(|err| PolicyRejection::new(format!("invalid volume create JSON: {err}")))?;
    reject_duplicate_json_keys(body)?;
    let obj = root
        .as_object_mut()
        .ok_or_else(|| PolicyRejection::new("volume create body must be a JSON object"))?;
    canonicalize_struct_keys(obj, KNOWN_VOLUME_CREATE_FIELDS, "CreateVolume")?;

    if let Some(cluster) = obj.get("ClusterVolumeSpec") {
        if !cluster.is_null() {
            return Err(PolicyRejection::new(
                "CreateVolume.ClusterVolumeSpec is forbidden inside sandbox isolation",
            ));
        }
    }

    if let Some(name_val) = obj.get("Name") {
        if !name_val.is_null() {
            let name = name_val
                .as_str()
                .ok_or_else(|| PolicyRejection::new("CreateVolume.Name must be a string"))?;
            if !name.is_empty() && !is_safe_volume_name(name) {
                return Err(PolicyRejection::new(format!(
                    "unsafe volume Name '{name}' is forbidden"
                )));
            }
        }
    }

    if let Some(driver_val) = obj.get("Driver") {
        if !driver_val.is_null() {
            let driver = driver_val
                .as_str()
                .ok_or_else(|| PolicyRejection::new("CreateVolume.Driver must be a string"))?
                .trim();
            if !driver.is_empty() && !driver.eq_ignore_ascii_case("local") {
                return Err(PolicyRejection::new(format!(
                    "CreateVolume.Driver '{driver}' is forbidden; only 'local' is permitted"
                )));
            }
        }
    }

    if let Some(opts_val) = obj.get("DriverOpts") {
        validate_volume_driver_options(opts_val, "CreateVolume.DriverOpts")?;
    }

    serde_json::to_vec(&root)
        .map_err(|err| PolicyRejection::new(format!("failed to serialize volume JSON: {err}")))
}

/// Validates and rewrites a Docker `POST /containers/{id}/exec` JSON body, rejecting
/// `Privileged: true` and injecting default container proxy environment variables when configured.
pub fn sanitize_exec_create(
    body: &[u8],
    policy: &DockerCompatPolicy,
) -> Result<Vec<u8>, PolicyRejection> {
    let mut root: Value = serde_json::from_slice(body)
        .map_err(|err| PolicyRejection::new(format!("invalid exec create JSON: {err}")))?;
    reject_duplicate_json_keys(body)?;
    let obj = root
        .as_object_mut()
        .ok_or_else(|| PolicyRejection::new("exec create body must be a JSON object"))?;
    canonicalize_struct_keys(obj, KNOWN_EXEC_CREATE_FIELDS, "ExecCreate")?;

    if let Some(priv_val) = obj.get("Privileged") {
        if !priv_val.is_null() {
            let is_priv = priv_val
                .as_bool()
                .ok_or_else(|| PolicyRejection::new("ExecCreate.Privileged must be a boolean"))?;
            if is_priv {
                return Err(PolicyRejection::new(
                    "ExecCreate.Privileged=true is forbidden inside sandbox isolation",
                ));
            }
        }
    }

    if let Some(proxy_url) = policy.container_proxy_http_url.as_deref() {
        inject_container_proxy_env(obj, proxy_url)?;
    }

    serde_json::to_vec(&root)
        .map_err(|err| PolicyRejection::new(format!("failed to serialize exec JSON: {err}")))
}

/// Validates and rewrites a Docker `POST /networks/create` JSON body, blocking `"host"`,
/// `"macvlan"`, and `"ipvlan"` network drivers/names and unsafe driver options.
pub fn sanitize_network_create(body: &[u8]) -> Result<Vec<u8>, PolicyRejection> {
    let mut root: Value = serde_json::from_slice(body)
        .map_err(|err| PolicyRejection::new(format!("invalid network create JSON: {err}")))?;
    reject_duplicate_json_keys(body)?;
    let obj = root
        .as_object_mut()
        .ok_or_else(|| PolicyRejection::new("network create body must be a JSON object"))?;
    canonicalize_struct_keys(obj, KNOWN_NETWORK_CREATE_FIELDS, "NetworkCreate")?;

    let name = obj
        .get("Name")
        .and_then(Value::as_str)
        .ok_or_else(|| PolicyRejection::new("NetworkCreate.Name must be a non-empty string"))?
        .trim();
    if !is_safe_custom_network_name(name) {
        return Err(PolicyRejection::new(format!(
            "NetworkCreate.Name '{name}' is forbidden"
        )));
    }

    if let Some(driver_val) = obj.get("Driver") {
        if !driver_val.is_null() {
            let driver = driver_val
                .as_str()
                .ok_or_else(|| PolicyRejection::new("NetworkCreate.Driver must be a string"))?
                .trim();
            if !driver.is_empty()
                && !driver.eq_ignore_ascii_case("bridge")
                && !driver.eq_ignore_ascii_case("null")
            {
                return Err(PolicyRejection::new(format!(
                    "NetworkCreate.Driver '{driver}' is forbidden"
                )));
            }
        }
    }

    if let Some(cfg_from) = obj.get("ConfigFrom") {
        if !cfg_from.is_null() {
            let is_empty = cfg_from.as_object().is_some_and(|m| {
                m.is_empty()
                    || m.get("Network")
                        .and_then(Value::as_str)
                        .is_some_and(str::is_empty)
            });
            if !is_empty {
                return Err(PolicyRejection::new(
                    "NetworkCreate.ConfigFrom is forbidden inside sandbox isolation",
                ));
            }
        }
    }

    if let Some(opts_val) = obj.get("Options") {
        if !opts_val.is_null() {
            let map = opts_val
                .as_object()
                .ok_or_else(|| PolicyRejection::new("NetworkCreate.Options must be a JSON object"))?;
            for (k, v) in map {
                if !k.is_ascii() {
                    return Err(PolicyRejection::new(format!(
                        "non-ASCII NetworkCreate.Options key '{k}' is forbidden"
                    )));
                }
                let kl = k.to_ascii_lowercase();
                let vs = v.as_str().unwrap_or("");
                if matches!(
                    kl.as_str(),
                    "parent"
                        | "host_interface"
                        | "mode"
                        | "com.docker.network.bridge.name"
                        | "com.docker.network.driver.mtu"
                ) || vs.contains('/')
                    || vs.contains('\\')
                {
                    return Err(PolicyRejection::new(format!(
                        "unsafe NetworkCreate.Options entry '{k}' is forbidden"
                    )));
                }
            }
        }
    }

    serde_json::to_vec(&root)
        .map_err(|err| PolicyRejection::new(format!("failed to serialize network JSON: {err}")))
}

/// Validates and rewrites a Docker `POST /networks/{id}/connect` JSON body, blocking attachment
/// to the `"host"` network.
pub fn sanitize_network_connect(
    network_id_or_name: &str,
    body: &[u8],
) -> Result<Vec<u8>, PolicyRejection> {
    let trimmed = network_id_or_name.trim();
    if trimmed.is_empty()
        || trimmed.eq_ignore_ascii_case("host")
        || trimmed.eq_ignore_ascii_case("macvlan")
        || trimmed.eq_ignore_ascii_case("ipvlan")
    {
        return Err(PolicyRejection::new(format!(
            "connecting container to network '{trimmed}' is forbidden"
        )));
    }

    let mut root: Value = serde_json::from_slice(body)
        .map_err(|err| PolicyRejection::new(format!("invalid network connect JSON: {err}")))?;
    reject_duplicate_json_keys(body)?;
    let obj = root
        .as_object_mut()
        .ok_or_else(|| PolicyRejection::new("network connect body must be a JSON object"))?;
    canonicalize_struct_keys(obj, KNOWN_NETWORK_CONNECT_FIELDS, "NetworkConnect")?;

    serde_json::to_vec(&root).map_err(|err| {
        PolicyRejection::new(format!("failed to serialize network connect JSON: {err}"))
    })
}

/// Validates query parameters on `POST /build` before streaming the build-context tar archive.
// shortcut: strict allowlist of standard Docker POST /build v1 query params blocks Podman/BuildKit host/privilege flags, extend allowlist if post-MVP BuildKit parity is added
pub fn validate_image_build_query(
    decoded_params: &[(String, String)],
) -> Result<(), PolicyRejection> {
    for (raw_key, val) in decoded_params {
        if !raw_key.is_ascii() {
            return Err(PolicyRejection::new(
                "non-ASCII query parameter in POST /build is forbidden",
            ));
        }
        let key = raw_key.to_ascii_lowercase();
        match key.as_str() {
            "networkmode" => {
                let mode = val.trim();
                if !mode.is_empty()
                    && !matches!(
                        mode.to_ascii_lowercase().as_str(),
                        "default" | "bridge" | "none" | "private"
                    )
                {
                    return Err(PolicyRejection::new(format!(
                        "POST /build networkmode='{mode}' is forbidden"
                    )));
                }
            }
            "dockerfile" => {
                let df = val.trim();
                if !df.is_empty()
                    && (df.contains('\0')
                        || df.contains('\\')
                        || df.starts_with('/')
                        || df.split('/').any(|seg| seg == ".."))
                {
                    return Err(PolicyRejection::new(format!(
                        "POST /build dockerfile='{df}' must be a safe archive-relative path"
                    )));
                }
            }
            "t" | "q" | "nocache" | "cachefrom" | "pull" | "rm" | "forcerm" | "buildargs"
            | "labels" | "target" | "platform" | "version" | "memory" | "memswap"
            | "cpushares" | "cpusetcpus" | "cpusetmems" | "cpuperiod" | "cpuquota" | "shmsize"
            | "squash" => {}
            _ => {
                return Err(PolicyRejection::new(format!(
                    "POST /build query parameter '{raw_key}' is forbidden"
                )));
            }
        }
    }
    Ok(())
}

fn reject_duplicate_json_keys(body: &[u8]) -> Result<(), PolicyRejection> {
    fn skip_ws(b: &[u8], i: &mut usize) {
        while *i < b.len() && matches!(b[*i], b' ' | b'\t' | b'\r' | b'\n') {
            *i += 1;
        }
    }

    fn scan_string_end(b: &[u8], start_quote: usize) -> Result<usize, PolicyRejection> {
        let mut i = start_quote + 1;
        while i < b.len() {
            match b[i] {
                b'\\' => i += 2,
                b'"' => return Ok(i + 1),
                _ => i += 1,
            }
        }
        Err(PolicyRejection::new("unterminated JSON string"))
    }

    fn scan_value(b: &[u8], i: &mut usize, depth: usize) -> Result<(), PolicyRejection> {
        if depth > MAX_JSON_NESTING_DEPTH {
            return Err(PolicyRejection::new("JSON nesting depth exceeded"));
        }
        skip_ws(b, i);
        let Some(&ch) = b.get(*i) else {
            return Err(PolicyRejection::new("unexpected end of JSON payload"));
        };
        match ch {
            b'{' => {
                *i += 1;
                skip_ws(b, i);
                if b.get(*i) == Some(&b'}') {
                    *i += 1;
                    return Ok(());
                }
                let mut seen = BTreeSet::new();
                loop {
                    skip_ws(b, i);
                    if b.get(*i) != Some(&b'"') {
                        return Err(PolicyRejection::new("expected JSON object key string"));
                    }
                    let end = scan_string_end(b, *i)?;
                    let key: String = serde_json::from_slice(&b[*i..end]).map_err(|err| {
                        PolicyRejection::new(format!("invalid JSON object key: {err}"))
                    })?;
                    *i = end;
                    if !seen.insert(key.clone()) {
                        return Err(PolicyRejection::new(format!(
                            "duplicate JSON object key '{key}' is forbidden"
                        )));
                    }
                    skip_ws(b, i);
                    if b.get(*i) != Some(&b':') {
                        return Err(PolicyRejection::new("expected ':' after JSON object key"));
                    }
                    *i += 1;
                    scan_value(b, i, depth + 1)?;
                    skip_ws(b, i);
                    match b.get(*i) {
                        Some(b',') => *i += 1,
                        Some(b'}') => {
                            *i += 1;
                            return Ok(());
                        }
                        _ => {
                            return Err(PolicyRejection::new(
                                "expected ',' or '}' in JSON object",
                            ));
                        }
                    }
                }
            }
            b'[' => {
                *i += 1;
                skip_ws(b, i);
                if b.get(*i) == Some(&b']') {
                    *i += 1;
                    return Ok(());
                }
                loop {
                    scan_value(b, i, depth + 1)?;
                    skip_ws(b, i);
                    match b.get(*i) {
                        Some(b',') => *i += 1,
                        Some(b']') => {
                            *i += 1;
                            return Ok(());
                        }
                        _ => {
                            return Err(PolicyRejection::new(
                                "expected ',' or ']' in JSON array",
                            ));
                        }
                    }
                }
            }
            b'"' => {
                *i = scan_string_end(b, *i)?;
                Ok(())
            }
            _ => {
                while *i < b.len()
                    && !matches!(b[*i], b' ' | b'\t' | b'\r' | b'\n' | b',' | b']' | b'}')
                {
                    *i += 1;
                }
                Ok(())
            }
        }
    }

    let mut idx = 0usize;
    scan_value(body, &mut idx, 0)
}

fn canonicalize_struct_keys(
    obj: &mut Map<String, Value>,
    known_fields: &[&str],
    context: &str,
) -> Result<(), PolicyRejection> {
    let mut seen_ci = BTreeSet::new();
    let entries: Vec<(String, Value)> = std::mem::take(obj).into_iter().collect();
    for (raw_key, val) in entries {
        if !raw_key.is_ascii() {
            return Err(PolicyRejection::new(format!(
                "non-ASCII field '{raw_key}' in {context} is forbidden"
            )));
        }
        let lower = raw_key.to_ascii_lowercase();
        if !seen_ci.insert(lower) {
            return Err(PolicyRejection::new(format!(
                "ambiguous case-colliding field '{raw_key}' in {context}"
            )));
        }
        let canonical = known_fields
            .iter()
            .copied()
            .find(|candidate| candidate.eq_ignore_ascii_case(&raw_key))
            .map(str::to_owned)
            .unwrap_or(raw_key);
        obj.insert(canonical, val);
    }
    Ok(())
}

fn inject_container_proxy_env(
    root_obj: &mut Map<String, Value>,
    proxy_url: &str,
) -> Result<(), PolicyRejection> {
    if proxy_url.is_empty() || proxy_url.chars().any(char::is_control) {
        return Err(PolicyRejection::new(
            "container_proxy_http_url must be a non-empty single-line URL",
        ));
    }

    let mut env_entries = match root_obj.get("Env") {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::Array(items)) => {
            for item in items {
                if !item.is_string() {
                    return Err(PolicyRejection::new("Env entries must be strings"));
                }
            }
            items.clone()
        }
        Some(_) => {
            return Err(PolicyRejection::new(
                "Env must be a JSON array of strings when provided",
            ));
        }
    };

    let mut existing_keys = BTreeSet::new();
    for item in &env_entries {
        if let Some(entry) = item.as_str() {
            let key = entry.split_once('=').map(|(k, _)| k).unwrap_or(entry);
            existing_keys.insert(key.to_owned());
        }
    }

    let defaults = [
        ("HTTP_PROXY", proxy_url),
        ("HTTPS_PROXY", proxy_url),
        ("ALL_PROXY", proxy_url),
        ("http_proxy", proxy_url),
        ("https_proxy", proxy_url),
        ("all_proxy", proxy_url),
        ("NO_PROXY", DEFAULT_CONTAINER_NO_PROXY),
        ("no_proxy", DEFAULT_CONTAINER_NO_PROXY),
    ];
    for (key, value) in defaults {
        if existing_keys.insert(key.to_owned()) {
            env_entries.push(Value::String(format!("{key}={value}")));
        }
    }

    root_obj.insert("Env".to_owned(), Value::Array(env_entries));
    Ok(())
}

fn validate_networking_config(net_cfg: &mut Value) -> Result<(), PolicyRejection> {
    if net_cfg.is_null() {
        return Ok(());
    }
    let obj = net_cfg
        .as_object_mut()
        .ok_or_else(|| PolicyRejection::new("NetworkingConfig must be a JSON object"))?;
    canonicalize_struct_keys(obj, KNOWN_NETWORKING_CONFIG_FIELDS, "NetworkingConfig")?;
    if let Some(endpoints) = obj.get("EndpointsConfig") {
        if !endpoints.is_null() {
            let ep_map = endpoints.as_object().ok_or_else(|| {
                PolicyRejection::new("NetworkingConfig.EndpointsConfig must be a JSON object")
            })?;
            for net_name in ep_map.keys() {
                if !is_allowed_endpoint_network_name(net_name) {
                    return Err(PolicyRejection::new(format!(
                        "NetworkingConfig.EndpointsConfig network '{net_name}' is forbidden"
                    )));
                }
            }
        }
    }
    Ok(())
}

fn validate_top_level_volumes(volumes: &Value) -> Result<(), PolicyRejection> {
    if volumes.is_null() {
        return Ok(());
    }
    let map = volumes
        .as_object()
        .ok_or_else(|| PolicyRejection::new("Volumes must be a JSON object"))?;
    for key in map.keys() {
        if key.contains(':') || key.contains('\\') || !is_safe_container_path(key) {
            return Err(PolicyRejection::new(format!(
                "unsafe or host-bound Volumes key '{key}' is forbidden"
            )));
        }
    }
    Ok(())
}

fn collect_exposed_tcp_ports(exposed: &Value) -> Result<Vec<(u16, String)>, PolicyRejection> {
    if exposed.is_null() {
        return Ok(Vec::new());
    }
    let map = exposed
        .as_object()
        .ok_or_else(|| PolicyRejection::new("ExposedPorts must be a JSON object"))?;

    let mut tcp_ports = Vec::new();
    let mut seen = BTreeSet::new();
    for key in map.keys() {
        let (port, proto) = parse_port_key(key)?;
        if proto == "tcp" && seen.insert(port) {
            tcp_ports.push((port, format!("{port}/tcp")));
        }
    }
    Ok(tcp_ports)
}

fn validate_host_config_security(
    hc: &mut Map<String, Value>,
    policy: &DockerCompatPolicy,
) -> Result<(), PolicyRejection> {
    if let Some(privileged) = hc.get("Privileged") {
        if !privileged.is_null() {
            let is_priv = privileged.as_bool().ok_or_else(|| {
                PolicyRejection::new("HostConfig.Privileged must be a boolean")
            })?;
            if is_priv {
                return Err(PolicyRejection::new(
                    "HostConfig.Privileged=true is forbidden inside sandbox isolation",
                ));
            }
        }
    }

    for field in [
        "PidMode",
        "NetworkMode",
        "IpcMode",
        "UsernsMode",
        "UTSMode",
        "CgroupnsMode",
    ] {
        if let Some(val) = hc.get(field) {
            if val.is_null() {
                continue;
            }
            let mode = val
                .as_str()
                .ok_or_else(|| PolicyRejection::new(format!("HostConfig.{field} must be a string")))?
                .trim();
            if !is_allowed_namespace_mode(field, mode) {
                return Err(PolicyRejection::new(format!(
                    "HostConfig.{field}='{mode}' is forbidden inside sandbox isolation"
                )));
            }
        }
    }

    if let Some(binds) = hc.get_mut("Binds") {
        sanitize_binds(binds, policy.reaper_socket)?;
    }

    if let Some(mounts) = hc.get_mut("Mounts") {
        sanitize_mounts(mounts, policy.reaper_socket)?;
    }

    for list_field in [
        "Devices",
        "DeviceCgroupRules",
        "DeviceRequests",
        "CapAdd",
        "VolumesFrom",
    ] {
        if let Some(val) = hc.get(list_field) {
            if !val.is_null() {
                let arr = val.as_array().ok_or_else(|| {
                    PolicyRejection::new(format!("HostConfig.{list_field} must be a JSON array"))
                })?;
                if !arr.is_empty() {
                    return Err(PolicyRejection::new(format!(
                        "HostConfig.{list_field} is forbidden inside sandbox isolation"
                    )));
                }
            }
        }
    }

    for mask_field in ["MaskedPaths", "ReadonlyPaths"] {
        if let Some(val) = hc.get(mask_field) {
            if !val.is_null() {
                return Err(PolicyRejection::new(format!(
                    "HostConfig.{mask_field} customization is forbidden inside sandbox isolation"
                )));
            }
        }
    }

    for map_field in ["Annotations", "Sysctls", "StorageOpt"] {
        if let Some(val) = hc.get(map_field) {
            if !val.is_null() {
                let obj = val.as_object().ok_or_else(|| {
                    PolicyRejection::new(format!("HostConfig.{map_field} must be a JSON object"))
                })?;
                if !obj.is_empty() {
                    return Err(PolicyRejection::new(format!(
                        "HostConfig.{map_field} is forbidden inside sandbox isolation"
                    )));
                }
            }
        }
    }

    for str_field in [
        "VolumeDriver",
        "CgroupParent",
        "Cgroup",
        "Runtime",
        "ContainerIDFile",
    ] {
        if let Some(val) = hc.get(str_field) {
            if !val.is_null() {
                let s = val.as_str().ok_or_else(|| {
                    PolicyRejection::new(format!("HostConfig.{str_field} must be a string"))
                })?;
                if !s.trim().is_empty() {
                    return Err(PolicyRejection::new(format!(
                        "HostConfig.{str_field}='{s}' is forbidden inside sandbox isolation"
                    )));
                }
            }
        }
    }

    if let Some(oom_kill_disable) = hc.get("OomKillDisable") {
        if !oom_kill_disable.is_null() {
            let disabled = oom_kill_disable.as_bool().ok_or_else(|| {
                PolicyRejection::new("HostConfig.OomKillDisable must be a boolean")
            })?;
            if disabled {
                return Err(PolicyRejection::new(
                    "HostConfig.OomKillDisable=true is forbidden inside sandbox isolation",
                ));
            }
        }
    }

    if let Some(oom_score) = hc.get("OomScoreAdj") {
        if !oom_score.is_null() {
            let score = oom_score.as_i64().ok_or_else(|| {
                PolicyRejection::new("HostConfig.OomScoreAdj must be an integer")
            })?;
            if !(0..=1000).contains(&score) {
                return Err(PolicyRejection::new(format!(
                    "HostConfig.OomScoreAdj={score} is outside permitted range 0..=1000"
                )));
            }
        }
    }

    if let Some(log_cfg) = hc.get_mut("LogConfig") {
        if !log_cfg.is_null() {
            let log_obj = log_cfg.as_object_mut().ok_or_else(|| {
                PolicyRejection::new("HostConfig.LogConfig must be a JSON object")
            })?;
            canonicalize_struct_keys(log_obj, KNOWN_LOG_CONFIG_FIELDS, "HostConfig.LogConfig")?;
            if let Some(driver_val) = log_obj.get("Type") {
                if !driver_val.is_null() {
                    let driver = driver_val.as_str().ok_or_else(|| {
                        PolicyRejection::new("HostConfig.LogConfig.Type must be a string")
                    })?;
                    let norm = driver.trim().to_ascii_lowercase();
                    if !matches!(
                        norm.as_str(),
                        "" | "json-file" | "k8s-file" | "journald" | "none" | "local"
                    ) {
                        return Err(PolicyRejection::new(format!(
                            "HostConfig.LogConfig.Type='{driver}' is forbidden inside sandbox isolation"
                        )));
                    }
                }
            }
            if let Some(cfg_val) = log_obj.get("Config") {
                if !cfg_val.is_null() {
                    let cfg_map = cfg_val.as_object().ok_or_else(|| {
                        PolicyRejection::new("HostConfig.LogConfig.Config must be a JSON object")
                    })?;
                    for (k, v) in cfg_map {
                        let vs = v.as_str().ok_or_else(|| {
                            PolicyRejection::new(format!(
                                "HostConfig.LogConfig.Config['{k}'] must be a string"
                            ))
                        })?;
                        if k.contains('\0') || vs.contains('\0') {
                            return Err(PolicyRejection::new(
                                "HostConfig.LogConfig.Config contains forbidden NUL byte",
                            ));
                        }
                        let k_lower = k.trim().to_ascii_lowercase();
                        if !matches!(
                            k_lower.as_str(),
                            "max-size"
                                | "max-file"
                                | "compress"
                                | "mode"
                                | "max-buffer-size"
                                | "labels"
                                | "labels-regex"
                                | "env"
                                | "env-regex"
                        ) {
                            return Err(PolicyRejection::new(format!(
                                "HostConfig.LogConfig.Config key '{k}' is forbidden inside sandbox isolation"
                            )));
                        }
                    }
                }
            }
        }
    }

    if let Some(tmpfs) = hc.get("Tmpfs") {
        if !tmpfs.is_null() {
            let tmpfs_map = tmpfs.as_object().ok_or_else(|| {
                PolicyRejection::new("HostConfig.Tmpfs must be a JSON object")
            })?;
            for (path_key, opts_val) in tmpfs_map {
                if path_key.contains(':')
                    || path_key.contains('\\')
                    || !is_safe_container_path(path_key)
                {
                    return Err(PolicyRejection::new(format!(
                        "unsafe HostConfig.Tmpfs path '{path_key}' is forbidden"
                    )));
                }
                let opts = opts_val.as_str().ok_or_else(|| {
                    PolicyRejection::new("HostConfig.Tmpfs option values must be strings")
                })?;
                validate_tmpfs_option_token(opts, "HostConfig.Tmpfs")?;
            }
        }
    }

    if let Some(sec_opt) = hc.get("SecurityOpt") {
        if !sec_opt.is_null() {
            let arr = sec_opt.as_array().ok_or_else(|| {
                PolicyRejection::new("HostConfig.SecurityOpt must be a JSON array")
            })?;
            for entry in arr {
                let opt = entry
                    .as_str()
                    .ok_or_else(|| {
                        PolicyRejection::new("HostConfig.SecurityOpt entries must be strings")
                    })?
                    .trim();
                if !matches!(
                    opt.to_ascii_lowercase().as_str(),
                    "no-new-privileges" | "no-new-privileges=true" | "no-new-privileges:true"
                ) {
                    return Err(PolicyRejection::new(format!(
                        "HostConfig.SecurityOpt '{opt}' is forbidden inside sandbox isolation"
                    )));
                }
            }
        }
    }

    Ok(())
}

fn sanitize_binds(binds: &mut Value, reaper_policy: ReaperSocketPolicy) -> Result<(), PolicyRejection> {
    if binds.is_null() {
        return Ok(());
    }
    let arr = binds
        .as_array_mut()
        .ok_or_else(|| PolicyRejection::new("HostConfig.Binds must be a JSON array"))?;

    for item in arr.iter_mut() {
        let entry = item
            .as_str()
            .ok_or_else(|| PolicyRejection::new("HostConfig.Binds entries must be strings"))?;
        let rewritten = sanitize_single_bind(entry, reaper_policy)?;
        *item = Value::String(rewritten);
    }
    Ok(())
}

fn sanitize_single_bind(
    entry: &str,
    reaper_policy: ReaperSocketPolicy,
) -> Result<String, PolicyRejection> {
    if let Some(suffix) = match_reaper_bind_suffix(entry) {
        return match reaper_policy {
            ReaperSocketPolicy::Deny => Err(PolicyRejection::new(
                "Docker socket bind mount is denied by ReaperSocketPolicy::Deny",
            )),
            ReaperSocketPolicy::MapGuestPodmanSocket => Ok(format!(
                "{GUEST_PODMAN_SOCKET_PATH}:{DOCKER_SOCKET_PATH}{suffix}"
            )),
        };
    }
    Err(PolicyRejection::new(format!(
        "unauthorized host bind mount '{entry}' is forbidden"
    )))
}

fn match_reaper_bind_suffix(entry: &str) -> Option<&'static str> {
    for src in [DOCKER_SOCKET_PATH, DOCKER_SOCKET_WIN_PREFIX_PATH] {
        let base = format!("{src}:{DOCKER_SOCKET_PATH}");
        if entry == base {
            return Some("");
        }
        if entry == format!("{base}:ro") {
            return Some(":ro");
        }
        if entry == format!("{base}:rw") {
            return Some(":rw");
        }
    }
    None
}

fn sanitize_mounts(
    mounts: &mut Value,
    reaper_policy: ReaperSocketPolicy,
) -> Result<(), PolicyRejection> {
    if mounts.is_null() {
        return Ok(());
    }
    let arr = mounts
        .as_array_mut()
        .ok_or_else(|| PolicyRejection::new("HostConfig.Mounts must be a JSON array"))?;

    for item in arr.iter_mut() {
        let obj = item
            .as_object_mut()
            .ok_or_else(|| PolicyRejection::new("HostConfig.Mounts entries must be JSON objects"))?;
        canonicalize_struct_keys(obj, KNOWN_MOUNT_FIELDS, "HostConfig.Mounts[]")?;
        if let Some(dest) = obj.remove("Destination") {
            match obj.get("Target") {
                None | Some(Value::Null) => {
                    obj.insert("Target".to_owned(), dest);
                }
                Some(existing) if existing == &dest => {}
                Some(_) => {
                    return Err(PolicyRejection::new(
                        "conflicting Target and Destination in HostConfig.Mounts entry",
                    ));
                }
            }
        }
        let mount_type = obj
            .get("Type")
            .and_then(Value::as_str)
            .ok_or_else(|| PolicyRejection::new("HostConfig.Mounts entry requires string Type"))?
            .trim()
            .to_ascii_lowercase();

        match mount_type.as_str() {
            "bind" => sanitize_bind_mount(obj, reaper_policy)?,
            "tmpfs" => sanitize_tmpfs_mount(obj)?,
            "volume" => sanitize_volume_mount(obj)?,
            other => {
                return Err(PolicyRejection::new(format!(
                    "HostConfig.Mounts type '{other}' is forbidden"
                )));
            }
        }
    }
    Ok(())
}

fn sanitize_bind_mount(
    obj: &mut Map<String, Value>,
    reaper_policy: ReaperSocketPolicy,
) -> Result<(), PolicyRejection> {
    let source = obj
        .get("Source")
        .and_then(Value::as_str)
        .ok_or_else(|| PolicyRejection::new("bind mount requires string Source"))?;
    let target = obj
        .get("Target")
        .and_then(Value::as_str)
        .ok_or_else(|| PolicyRejection::new("bind mount requires string Target"))?;

    let is_reaper_source =
        source == DOCKER_SOCKET_PATH || source == DOCKER_SOCKET_WIN_PREFIX_PATH;
    if is_reaper_source && target == DOCKER_SOCKET_PATH {
        return match reaper_policy {
            ReaperSocketPolicy::Deny => Err(PolicyRejection::new(
                "Docker socket bind mount is denied by ReaperSocketPolicy::Deny",
            )),
            ReaperSocketPolicy::MapGuestPodmanSocket => {
                obj.insert(
                    "Source".to_owned(),
                    Value::String(GUEST_PODMAN_SOCKET_PATH.to_owned()),
                );
                Ok(())
            }
        };
    }

    Err(PolicyRejection::new(format!(
        "unauthorized host bind mount '{source}' -> '{target}' is forbidden"
    )))
}

fn validate_tmpfs_option_token(opts: &str, ctx: &str) -> Result<(), PolicyRejection> {
    const ALLOWED_TMPFS_FLAGS: &[&str] = &[
        "rw",
        "ro",
        "nosuid",
        "nodev",
        "noexec",
        "exec",
        "atime",
        "noatime",
        "relatime",
        "norelatime",
        "strictatime",
        "nostrictatime",
        "diratime",
        "nodiratime",
        "lazytime",
        "nolazytime",
        "sync",
        "async",
        "dirsync",
        "mand",
        "nomand",
        "tmpcopyup",
        "notmpcopyup",
        "private",
        "rprivate",
        "nosymfollow",
    ];

    if opts.bytes().any(|b| b < 0x20 || b == 0x7f) {
        return Err(PolicyRejection::new(format!(
            "{ctx} option contains forbidden NUL or control character"
        )));
    }
    for raw in opts.split(',').map(str::trim).filter(|o| !o.is_empty()) {
        let (key_raw, val_opt) = raw
            .split_once('=')
            .map_or((raw, None), |(k, v)| (k.trim(), Some(v.trim())));
        let key = key_raw.to_ascii_lowercase();
        match key.as_str() {
            k if ALLOWED_TMPFS_FLAGS.contains(&k) => {
                if val_opt.is_some() {
                    return Err(PolicyRejection::new(format!(
                        "{ctx} flag option '{raw}' must not take a value"
                    )));
                }
            }
            "mode" => {
                let Some(mode_str) = val_opt.filter(|v| !v.is_empty()) else {
                    return Err(PolicyRejection::new(format!(
                        "{ctx} mount option '{raw}' requires an octal mode value"
                    )));
                };
                let perm = u32::from_str_radix(mode_str, 8).map_err(|_| {
                    PolicyRejection::new(format!(
                        "{ctx} mount option '{raw}' has invalid octal mode"
                    ))
                })?;
                if perm > 0o1777 {
                    return Err(PolicyRejection::new(format!(
                        "{ctx} mount mode '{mode_str}' exceeds maximum permitted 01777"
                    )));
                }
            }
            "size" => {
                let Some(size_str) = val_opt else {
                    return Err(PolicyRejection::new(format!(
                        "{ctx} mount option '{raw}' requires a size value"
                    )));
                };
                let valid = size_str.bytes().next().is_some_and(|b| b.is_ascii_digit())
                    && size_str
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'%');
                if !valid {
                    return Err(PolicyRejection::new(format!(
                        "{ctx} mount option '{raw}' has invalid size"
                    )));
                }
            }
            "nr_blocks" | "nr_inodes" => {
                let Some(count_str) = val_opt else {
                    return Err(PolicyRejection::new(format!(
                        "{ctx} mount option '{raw}' requires a count value"
                    )));
                };
                let valid = count_str.bytes().next().is_some_and(|b| b.is_ascii_digit())
                    && count_str.bytes().all(|b| b.is_ascii_alphanumeric());
                if !valid {
                    return Err(PolicyRejection::new(format!(
                        "{ctx} mount option '{raw}' has invalid block/inode limit"
                    )));
                }
            }
            "uid" | "gid" => {
                let Some(id_str) = val_opt else {
                    return Err(PolicyRejection::new(format!(
                        "{ctx} mount option '{raw}' requires a numeric ID"
                    )));
                };
                if id_str.is_empty()
                    || !id_str.bytes().all(|b| b.is_ascii_digit())
                    || id_str.parse::<u32>().is_err()
                {
                    return Err(PolicyRejection::new(format!(
                        "{ctx} mount option '{raw}' has invalid numeric ID"
                    )));
                }
            }
            "huge" => {
                let Some(huge_val) = val_opt else {
                    return Err(PolicyRejection::new(format!(
                        "{ctx} mount option '{raw}' requires a policy value"
                    )));
                };
                if !matches!(
                    huge_val.to_ascii_lowercase().as_str(),
                    "never" | "always" | "within_size" | "advise" | "deny" | "force"
                ) {
                    return Err(PolicyRejection::new(format!(
                        "{ctx} mount option '{raw}' has invalid huge page setting"
                    )));
                }
            }
            _ => {
                return Err(PolicyRejection::new(format!(
                    "{ctx} mount option '{raw}' is not in the permitted tmpfs allowlist"
                )));
            }
        }
    }
    Ok(())
}

fn sanitize_tmpfs_mount(obj: &mut Map<String, Value>) -> Result<(), PolicyRejection> {
    let target = obj
        .get("Target")
        .and_then(Value::as_str)
        .ok_or_else(|| PolicyRejection::new("tmpfs mount requires string Target"))?;
    if !is_safe_container_path(target) {
        return Err(PolicyRejection::new(format!(
            "invalid tmpfs mount Target '{target}'"
        )));
    }
    if let Some(src) = obj.get("Source") {
        if !src.is_null() && src.as_str() != Some("") {
            return Err(PolicyRejection::new(
                "tmpfs mount cannot specify a host Source",
            ));
        }
    }
    if let Some(tmpfs_opts) = obj.get_mut("TmpfsOptions") {
        if !tmpfs_opts.is_null() {
            let opts_obj = tmpfs_opts.as_object_mut().ok_or_else(|| {
                PolicyRejection::new("TmpfsOptions must be a JSON object")
            })?;
            canonicalize_struct_keys(opts_obj, KNOWN_TMPFS_OPTIONS_FIELDS, "TmpfsOptions")?;
            for key in opts_obj.keys() {
                if !KNOWN_TMPFS_OPTIONS_FIELDS.contains(&key.as_str()) {
                    return Err(PolicyRejection::new(format!(
                        "TmpfsOptions field '{key}' is forbidden inside sandbox isolation"
                    )));
                }
            }
            if let Some(size_val) = opts_obj.get("SizeBytes") {
                if !size_val.is_null() && !size_val.as_i64().is_some_and(|v| v >= 0) {
                    return Err(PolicyRejection::new(
                        "TmpfsOptions.SizeBytes must be a non-negative integer",
                    ));
                }
            }
            if let Some(mode_val) = opts_obj.get("Mode") {
                if !mode_val.is_null() && !mode_val.as_u64().is_some_and(|m| m <= 0o1777) {
                    return Err(PolicyRejection::new(
                        "TmpfsOptions.Mode must be an integer <= 01777",
                    ));
                }
            }
            if let Some(options_val) = opts_obj.get("Options") {
                if !options_val.is_null() {
                    let outer = options_val.as_array().ok_or_else(|| {
                        PolicyRejection::new("TmpfsOptions.Options must be a JSON array")
                    })?;
                    for pair_val in outer {
                        let pair = pair_val.as_array().ok_or_else(|| {
                            PolicyRejection::new(
                                "TmpfsOptions.Options entries must be string arrays",
                            )
                        })?;
                        if pair.is_empty() || pair.len() > 2 {
                            return Err(PolicyRejection::new(
                                "TmpfsOptions.Options entries must contain 1 or 2 strings",
                            ));
                        }
                        let k = pair[0].as_str().ok_or_else(|| {
                            PolicyRejection::new("TmpfsOptions.Options entries must be strings")
                        })?;
                        if k.trim().is_empty() {
                            return Err(PolicyRejection::new(
                                "TmpfsOptions.Options entry cannot be empty",
                            ));
                        }
                        if pair.len() == 2 {
                            let v = pair[1].as_str().ok_or_else(|| {
                                PolicyRejection::new("TmpfsOptions.Options entries must be strings")
                            })?;
                            if k.contains([',', '=']) || v.contains([',', '=']) {
                                return Err(PolicyRejection::new(
                                    "TmpfsOptions.Options key/value pair must not contain ',' or '='",
                                ));
                            }
                            validate_tmpfs_option_token(
                                &format!("{k}={v}"),
                                "TmpfsOptions.Options",
                            )?;
                        } else {
                            validate_tmpfs_option_token(k, "TmpfsOptions.Options")?;
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

fn sanitize_volume_mount(obj: &mut Map<String, Value>) -> Result<(), PolicyRejection> {
    let target = obj
        .get("Target")
        .and_then(Value::as_str)
        .ok_or_else(|| PolicyRejection::new("volume mount requires string Target"))?;
    if !is_safe_container_path(target) {
        return Err(PolicyRejection::new(format!(
            "invalid volume mount Target '{target}'"
        )));
    }

    if let Some(src_val) = obj.get("Source") {
        if !src_val.is_null() {
            let src = src_val.as_str().ok_or_else(|| {
                PolicyRejection::new("volume mount Source must be a string when provided")
            })?;
            if !src.is_empty() && !is_safe_volume_name(src) {
                return Err(PolicyRejection::new(format!(
                    "unsafe volume mount Source '{src}': named volumes cannot contain path separators or drive letters"
                )));
            }
        }
    }

    if let Some(vol_opts) = obj.get_mut("VolumeOptions") {
        if !vol_opts.is_null() {
            let opts_obj = vol_opts.as_object_mut().ok_or_else(|| {
                PolicyRejection::new("VolumeOptions must be a JSON object")
            })?;
            canonicalize_struct_keys(opts_obj, KNOWN_VOLUME_OPTIONS_FIELDS, "VolumeOptions")?;
            if let Some(subpath) = opts_obj.get("Subpath").and_then(Value::as_str) {
                if subpath.contains("..") || subpath.starts_with('/') || subpath.contains('\\') {
                    return Err(PolicyRejection::new(format!(
                        "unsafe VolumeOptions.Subpath '{subpath}' is forbidden"
                    )));
                }
            }
            if let Some(driver_cfg) = opts_obj.get_mut("DriverConfig") {
                if !driver_cfg.is_null() {
                    let dc_obj = driver_cfg.as_object_mut().ok_or_else(|| {
                        PolicyRejection::new("VolumeOptions.DriverConfig must be a JSON object")
                    })?;
                    canonicalize_struct_keys(
                        dc_obj,
                        KNOWN_DRIVER_CONFIG_FIELDS,
                        "VolumeOptions.DriverConfig",
                    )?;
                    if let Some(driver_opts) = dc_obj.get("Options") {
                        validate_volume_driver_options(
                            driver_opts,
                            "VolumeOptions.DriverConfig.Options",
                        )?;
                    }
                }
            }
        }
    }

    Ok(())
}

fn normalize_host_config_ports(
    hc: &mut Map<String, Value>,
    exposed_tcp_ports: &[(u16, String)],
) -> Result<Vec<RequestedPortBinding>, PolicyRejection> {
    let mut requested = Vec::new();
    let mut normalized_map = Map::new();

    if let Some(pb_val) = hc.get("PortBindings") {
        if !pb_val.is_null() {
            let pb_obj = pb_val.as_object().ok_or_else(|| {
                PolicyRejection::new("HostConfig.PortBindings must be a JSON object")
            })?;

            for (raw_key, raw_list) in pb_obj {
                let (container_port, proto) = parse_port_key(raw_key)?;
                if proto != "tcp" {
                    return Err(PolicyRejection::new(format!(
                        "non-TCP published port '{raw_key}' is not supported"
                    )));
                }
                let canonical_key = format!("{container_port}/tcp");
                if normalized_map.contains_key(&canonical_key) {
                    return Err(PolicyRejection::new(format!(
                        "duplicate PortBindings entry for '{canonical_key}'"
                    )));
                }

                if raw_list.is_null() {
                    requested.push(RequestedPortBinding {
                        container_port,
                        protocol: "tcp".to_owned(),
                        host_port: None,
                        container_key: canonical_key.clone(),
                    });
                } else {
                    let entries = raw_list.as_array().ok_or_else(|| {
                        PolicyRejection::new(format!(
                            "PortBindings['{raw_key}'] must be a JSON array"
                        ))
                    })?;
                    if entries.is_empty() {
                        requested.push(RequestedPortBinding {
                            container_port,
                            protocol: "tcp".to_owned(),
                            host_port: None,
                            container_key: canonical_key.clone(),
                        });
                    } else {
                        for entry in entries {
                            let mut binding = entry
                                .as_object()
                                .ok_or_else(|| {
                                    PolicyRejection::new(format!(
                                        "PortBindings['{raw_key}'] entries must be objects"
                                    ))
                                })?
                                .clone();
                            canonicalize_struct_keys(
                                &mut binding,
                                KNOWN_PORT_BINDING_FIELDS,
                                "PortBindings[]",
                            )?;
                            validate_host_ip(binding.get("HostIp"))?;
                            let host_port = parse_host_port(binding.get("HostPort"))?;
                            requested.push(RequestedPortBinding {
                                container_port,
                                protocol: "tcp".to_owned(),
                                host_port,
                                container_key: canonical_key.clone(),
                            });
                        }
                    }
                }

                normalized_map.insert(canonical_key, loopback_ephemeral_binding());
            }
        }
    }

    let publish_all = match hc.get("PublishAllPorts") {
        Some(v) if !v.is_null() => v.as_bool().ok_or_else(|| {
            PolicyRejection::new("HostConfig.PublishAllPorts must be a boolean")
        })?,
        _ => false,
    };

    if publish_all {
        for (container_port, canonical_key) in exposed_tcp_ports {
            if !normalized_map.contains_key(canonical_key) {
                normalized_map.insert(canonical_key.clone(), loopback_ephemeral_binding());
                requested.push(RequestedPortBinding {
                    container_port: *container_port,
                    protocol: "tcp".to_owned(),
                    host_port: None,
                    container_key: canonical_key.clone(),
                });
            }
        }
        hc.insert("PublishAllPorts".to_owned(), Value::Bool(false));
    }

    if !normalized_map.is_empty() {
        hc.insert("PortBindings".to_owned(), Value::Object(normalized_map));
    }

    Ok(requested)
}

fn loopback_ephemeral_binding() -> Value {
    json!([{ "HostIp": "127.0.0.1", "HostPort": "" }])
}

fn validate_host_ip(val: Option<&Value>) -> Result<(), PolicyRejection> {
    let Some(v) = val else {
        return Ok(());
    };
    if v.is_null() {
        return Ok(());
    }
    let ip = v
        .as_str()
        .ok_or_else(|| PolicyRejection::new("PortBindings HostIp must be a string"))?;
    match ip {
        "" | "127.0.0.1" | "0.0.0.0" | "::1" => Ok(()),
        other => Err(PolicyRejection::new(format!(
            "HostIp '{other}' outside loopback is forbidden"
        ))),
    }
}

fn parse_host_port(val: Option<&Value>) -> Result<Option<u16>, PolicyRejection> {
    let Some(v) = val else {
        return Ok(None);
    };
    if v.is_null() {
        return Ok(None);
    }
    let raw = v
        .as_str()
        .ok_or_else(|| PolicyRejection::new("PortBindings HostPort must be a string"))?;
    if raw.is_empty() || raw == "0" {
        return Ok(None);
    }
    if !raw.bytes().all(|b| b.is_ascii_digit()) {
        return Err(PolicyRejection::new(format!(
            "invalid HostPort '{raw}': must be numeric port or empty"
        )));
    }
    let port: u16 = raw
        .parse()
        .map_err(|_| PolicyRejection::new(format!("HostPort '{raw}' out of range")))?;
    if port == 0 {
        return Ok(None);
    }
    Ok(Some(port))
}

pub(crate) fn parse_port_key(key: &str) -> Result<(u16, String), PolicyRejection> {
    let (port_str, proto) = match key.split_once('/') {
        Some((p, pr)) => {
            if pr.contains('/') || pr.is_empty() {
                return Err(PolicyRejection::new(format!("invalid port spec '{key}'")));
            }
            (p, pr.to_ascii_lowercase())
        }
        None => (key, "tcp".to_owned()),
    };

    if port_str.is_empty() || !port_str.bytes().all(|b| b.is_ascii_digit()) {
        return Err(PolicyRejection::new(format!("invalid port number '{key}'")));
    }
    let port: u16 = port_str
        .parse()
        .map_err(|_| PolicyRejection::new(format!("port number out of range in '{key}'")))?;
    if port == 0 {
        return Err(PolicyRejection::new(format!(
            "port 0 is not a valid container port in '{key}'"
        )));
    }
    Ok((port, proto))
}

fn is_safe_container_path(path: &str) -> bool {
    if !path.starts_with('/') || path.contains('\\') || path.contains('\0') {
        return false;
    }
    !path.split('/').any(|seg| seg == "..")
}

fn validate_volume_driver_options(opts: &Value, context: &str) -> Result<(), PolicyRejection> {
    if opts.is_null() {
        return Ok(());
    }
    let d_map = opts
        .as_object()
        .ok_or_else(|| PolicyRejection::new(format!("{context} must be a JSON object")))?;
    for (k, v) in d_map {
        if !k.is_ascii() {
            return Err(PolicyRejection::new(format!(
                "non-ASCII {context} option '{k}' is forbidden"
            )));
        }
        let key_lower = k.to_ascii_lowercase();
        let val_str = v.as_str().unwrap_or("");
        if matches!(key_lower.as_str(), "device" | "o" | "type")
            || val_str.contains('/')
            || val_str.contains('\\')
        {
            return Err(PolicyRejection::new(format!(
                "unsafe {context} option '{k}' is forbidden"
            )));
        }
    }
    Ok(())
}

fn is_safe_container_ref(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && !s.starts_with('-')
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
}

fn is_safe_custom_network_name(name: &str) -> bool {
    if !is_safe_volume_name(name) || name.len() > 128 {
        return false;
    }
    !matches!(
        name.to_ascii_lowercase().as_str(),
        "host" | "macvlan" | "ipvlan"
    )
}

fn is_allowed_endpoint_network_name(name: &str) -> bool {
    let lower = name.trim().to_ascii_lowercase();
    if matches!(lower.as_str(), "bridge" | "none" | "default") {
        return true;
    }
    is_safe_custom_network_name(name.trim())
}

fn is_allowed_namespace_mode(field: &str, mode: &str) -> bool {
    if mode.is_empty() {
        return true;
    }
    let lower = mode.to_ascii_lowercase();
    match field {
        "PidMode" | "UTSMode" => {
            lower == "private"
                || mode
                    .strip_prefix("container:")
                    .is_some_and(is_safe_container_ref)
        }
        "IpcMode" => {
            matches!(lower.as_str(), "none" | "private" | "shareable")
                || mode
                    .strip_prefix("container:")
                    .is_some_and(is_safe_container_ref)
        }
        "UsernsMode" | "CgroupnsMode" => lower == "private",
        "NetworkMode" => {
            if matches!(
                lower.as_str(),
                "default" | "bridge" | "none" | "private" | "slirp4netns" | "pasta"
            ) {
                return true;
            }
            if let Some(target) = mode.strip_prefix("container:") {
                return is_safe_container_ref(target);
            }
            is_safe_custom_network_name(mode)
        }
        _ => false,
    }
}

fn is_safe_volume_name(name: &str) -> bool {
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !first.is_ascii_alphanumeric() {
        return false;
    }
    chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-')) && !name.contains("..")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_raw_host_bind_mounts_across_binds_mounts_and_volumes() {
        let deny_policy = DockerCompatPolicy::default();
        let map_policy = DockerCompatPolicy {
            reaper_socket: ReaperSocketPolicy::MapGuestPodmanSocket,
            ..Default::default()
        };

        let cases = [
            json!({ "Image": "alpine", "HostConfig": { "Binds": ["C:\\Users\\alice:/data"] } }),
            json!({ "Image": "alpine", "HostConfig": { "Binds": ["/Users/bob:/data"] } }),
            json!({ "Image": "alpine", "HostConfig": { "Binds": ["/home/u:/work:rw"] } }),
            json!({ "Image": "alpine", "HostConfig": { "Binds": ["./src:/app"] } }),
            json!({ "Image": "alpine", "HostConfig": { "Binds": ["/var/run/docker.sock:/evil"] } }),
            json!({ "Image": "alpine", "HostConfig": { "Binds": ["/var/run/docker.sock:/var/run/docker.sock:exec"] } }),
            json!({ "Image": "alpine", "HostConfig": { "Mounts": [{ "Type": "bind", "Source": "/etc", "Target": "/mnt" }] } }),
            json!({ "Image": "alpine", "HostConfig": { "Mounts": [{ "Type": "BIND", "Source": "/var/run/docker.sock", "Target": "/evil" }] } }),
            json!({ "Image": "alpine", "HostConfig": { "Mounts": [{ "Type": "volume", "Source": "/Users/bob/vol", "Target": "/data" }] } }),
            json!({ "Image": "alpine", "HostConfig": { "Mounts": [{ "Type": "volume", "Source": "C:\\vol", "Target": "/data" }] } }),
            json!({
                "Image": "alpine",
                "HostConfig": {
                    "Mounts": [{
                        "Type": "volume",
                        "Source": "sneaky",
                        "Target": "/data",
                        "VolumeOptions": {
                            "DriverConfig": {
                                "Name": "local",
                                "Options": { "type": "none", "o": "bind", "device": "/etc" }
                            }
                        }
                    }]
                }
            }),
            json!({ "Image": "alpine", "Volumes": { "C:\\Users\\alice:/data": {} } }),
            json!({ "Image": "alpine", "Volumes": { "/host:/data": {} } }),
        ];

        for case in &cases {
            let bytes = serde_json::to_vec(case).unwrap();
            assert!(
                sanitize_container_create(&bytes, &deny_policy).is_err(),
                "must reject under Deny: {case}"
            );
            assert!(
                sanitize_container_create(&bytes, &map_policy).is_err(),
                "must reject under MapGuestPodmanSocket: {case}"
            );
        }
    }

    #[test]
    fn rejects_privileged_and_host_namespace_modes() {
        let policy = DockerCompatPolicy::default();
        let cases = [
            json!({ "Image": "alpine", "HostConfig": { "Privileged": true } }),
            json!({ "Image": "alpine", "HostConfig": { "PidMode": "host" } }),
            json!({ "Image": "alpine", "HostConfig": { "NetworkMode": "HOST" } }),
            json!({ "Image": "alpine", "HostConfig": { "IpcMode": "host" } }),
            json!({ "Image": "alpine", "HostConfig": { "UsernsMode": "host" } }),
        ];

        for case in &cases {
            let bytes = serde_json::to_vec(case).unwrap();
            assert!(
                sanitize_container_create(&bytes, &policy).is_err(),
                "must reject dangerous host config: {case}"
            );
        }
    }

    #[test]
    fn reaper_socket_denied_by_default_and_mapped_when_enabled() {
        let deny = DockerCompatPolicy {
            reaper_socket: ReaperSocketPolicy::Deny,
            ..Default::default()
        };
        let map = DockerCompatPolicy {
            reaper_socket: ReaperSocketPolicy::MapGuestPodmanSocket,
            ..Default::default()
        };

        for (raw_bind, expected_bind) in [
            (
                "/var/run/docker.sock:/var/run/docker.sock",
                "/run/podman/podman.sock:/var/run/docker.sock",
            ),
            (
                "/var/run/docker.sock:/var/run/docker.sock:ro",
                "/run/podman/podman.sock:/var/run/docker.sock:ro",
            ),
            (
                "//var/run/docker.sock:/var/run/docker.sock:rw",
                "/run/podman/podman.sock:/var/run/docker.sock:rw",
            ),
        ] {
            let body = serde_json::to_vec(&json!({
                "Image": "testcontainers/ryuk:0.7.0",
                "HostConfig": { "Binds": [raw_bind] }
            }))
            .unwrap();
            assert!(sanitize_container_create(&body, &deny).is_err());

            let plan = sanitize_container_create(&body, &map).expect("reaper bind allowed");
            let rewritten: Value = serde_json::from_slice(&plan.rewritten_body).unwrap();
            assert_eq!(rewritten["HostConfig"]["Binds"][0], expected_bind);
        }

        // Also validate HostConfig.Mounts bind variant (including //var/run/docker.sock).
        for src in ["/var/run/docker.sock", "//var/run/docker.sock"] {
            let body = serde_json::to_vec(&json!({
                "Image": "testcontainers/ryuk:0.7.0",
                "HostConfig": {
                    "Mounts": [{
                        "Type": "BIND",
                        "Source": src,
                        "Target": "/var/run/docker.sock"
                    }]
                }
            }))
            .unwrap();
            assert!(sanitize_container_create(&body, &deny).is_err());

            let plan = sanitize_container_create(&body, &map).expect("reaper mount allowed");
            let rewritten: Value = serde_json::from_slice(&plan.rewritten_body).unwrap();
            assert_eq!(
                rewritten["HostConfig"]["Mounts"][0]["Source"],
                "/run/podman/podman.sock"
            );
        }
    }

    #[test]
    fn allows_tmpfs_and_safe_named_volumes() {
        let policy = DockerCompatPolicy::default();
        let body = serde_json::to_vec(&json!({
            "Image": "postgres:16",
            "Volumes": { "/var/lib/postgresql/data": {} },
            "HostConfig": {
                "NetworkMode": "bridge",
                "Mounts": [
                    { "Type": "tmpfs", "Target": "/tmp" },
                    { "Type": "volume", "Source": "pg_data-1.vol", "Target": "/var/lib/postgresql/data" }
                ]
            }
        }))
        .unwrap();

        let plan = sanitize_container_create(&body, &policy).expect("safe mounts allowed");
        assert!(plan.requested_ports.is_empty());
    }

    #[test]
    fn normalizes_port_bindings_and_publish_all_ports_to_loopback_ephemeral() {
        let policy = DockerCompatPolicy::default();
        let body = serde_json::to_vec(&json!({
            "Image": "redis:7",
            "ExposedPorts": {
                "5432/tcp": {},
                "6379": {},
                "53/udp": {}
            },
            "HostConfig": {
                "PublishAllPorts": true,
                "PortBindings": {
                    "6379": [{ "HostIp": "0.0.0.0", "HostPort": "16379" }],
                    "8080/tcp": [{ "HostIp": "", "HostPort": "" }],
                    "9090/tcp": [{ "HostIp": "127.0.0.1", "HostPort": "0" }]
                }
            }
        }))
        .unwrap();

        let plan = sanitize_container_create(&body, &policy).expect("valid ports normalize");
        assert_eq!(
            plan.requested_ports,
            vec![
                RequestedPortBinding {
                    container_port: 6379,
                    protocol: "tcp".to_owned(),
                    host_port: Some(16379),
                    container_key: "6379/tcp".to_owned(),
                },
                RequestedPortBinding {
                    container_port: 8080,
                    protocol: "tcp".to_owned(),
                    host_port: None,
                    container_key: "8080/tcp".to_owned(),
                },
                RequestedPortBinding {
                    container_port: 9090,
                    protocol: "tcp".to_owned(),
                    host_port: None,
                    container_key: "9090/tcp".to_owned(),
                },
                RequestedPortBinding {
                    container_port: 5432,
                    protocol: "tcp".to_owned(),
                    host_port: None,
                    container_key: "5432/tcp".to_owned(),
                },
            ]
        );

        let rewritten: Value = serde_json::from_slice(&plan.rewritten_body).unwrap();
        assert_eq!(rewritten["HostConfig"]["PublishAllPorts"], false);
        for key in ["5432/tcp", "6379/tcp", "8080/tcp", "9090/tcp"] {
            assert_eq!(
                rewritten["HostConfig"]["PortBindings"][key],
                json!([{ "HostIp": "127.0.0.1", "HostPort": "" }])
            );
        }
        assert!(rewritten["HostConfig"]["PortBindings"]
            .get("53/udp")
            .is_none());
    }

    #[test]
    fn rejects_non_tcp_published_ports_and_unsafe_host_ips() {
        let policy = DockerCompatPolicy::default();
        let udp_body = serde_json::to_vec(&json!({
            "Image": "coredns",
            "HostConfig": {
                "PortBindings": {
                    "53/udp": [{ "HostIp": "127.0.0.1", "HostPort": "5353" }]
                }
            }
        }))
        .unwrap();
        assert!(sanitize_container_create(&udp_body, &policy).is_err());

        let lan_ip_body = serde_json::to_vec(&json!({
            "Image": "nginx",
            "HostConfig": {
                "PortBindings": {
                    "80/tcp": [{ "HostIp": "192.168.1.10", "HostPort": "8080" }]
                }
            }
        }))
        .unwrap();
        assert!(sanitize_container_create(&lan_ip_body, &policy).is_err());

        let bad_host_port = serde_json::to_vec(&json!({
            "Image": "nginx",
            "HostConfig": {
                "PortBindings": {
                    "80/tcp": [{ "HostIp": "127.0.0.1", "HostPort": "8000-8010" }]
                }
            }
        }))
        .unwrap();
        assert!(sanitize_container_create(&bad_host_port, &policy).is_err());
    }

    #[test]
    fn publish_all_ports_without_port_bindings_populates_ephemeral_loopback() {
        let policy = DockerCompatPolicy::default();
        let body = serde_json::to_vec(&json!({
            "Image": "postgres:16",
            "ExposedPorts": { "5432/tcp": {} },
            "HostConfig": { "PublishAllPorts": true }
        }))
        .unwrap();

        let plan = sanitize_container_create(&body, &policy).expect("PublishAllPorts succeeds");
        assert_eq!(
            plan.requested_ports,
            vec![RequestedPortBinding {
                container_port: 5432,
                protocol: "tcp".to_owned(),
                host_port: None,
                container_key: "5432/tcp".to_owned(),
            }]
        );
        let rewritten: Value = serde_json::from_slice(&plan.rewritten_body).unwrap();
        assert_eq!(rewritten["HostConfig"]["PublishAllPorts"], false);
        assert_eq!(
            rewritten["HostConfig"]["PortBindings"]["5432/tcp"],
            json!([{ "HostIp": "127.0.0.1", "HostPort": "" }])
        );
    }

    #[test]
    fn injects_container_proxy_env_defaults_while_preserving_caller_overrides() {
        let proxy_url = "http://10.88.0.1:3128";
        let policy_disabled = DockerCompatPolicy::default();
        assert_eq!(policy_disabled.container_proxy_http_url, None);

        let policy_enabled = DockerCompatPolicy {
            reaper_socket: ReaperSocketPolicy::MapGuestPodmanSocket,
            container_proxy_http_url: Some(proxy_url.to_owned()),
        };

        // 1. Disabled policy leaves omitted Env untouched.
        let bare = serde_json::to_vec(&json!({ "Image": "alpine" })).unwrap();
        let plan_disabled = sanitize_container_create(&bare, &policy_disabled).unwrap();
        let val_disabled: Value = serde_json::from_slice(&plan_disabled.rewritten_body).unwrap();
        assert!(val_disabled.get("Env").is_none());

        // 2. Enabled policy injects all 8 proxy vars when Env is null or absent.
        let null_env = serde_json::to_vec(&json!({ "Image": "alpine", "Env": null })).unwrap();
        let plan_null = sanitize_container_create(&null_env, &policy_enabled).unwrap();
        let val_null: Value = serde_json::from_slice(&plan_null.rewritten_body).unwrap();
        let env_null: Vec<&str> = val_null["Env"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        for expected in [
            "HTTP_PROXY=http://10.88.0.1:3128",
            "HTTPS_PROXY=http://10.88.0.1:3128",
            "ALL_PROXY=http://10.88.0.1:3128",
            "http_proxy=http://10.88.0.1:3128",
            "https_proxy=http://10.88.0.1:3128",
            "all_proxy=http://10.88.0.1:3128",
            "NO_PROXY=localhost,127.0.0.1,::1,10.88.0.1",
            "no_proxy=localhost,127.0.0.1,::1,10.88.0.1",
        ] {
            assert!(env_null.contains(&expected), "missing {expected} in {env_null:?}");
        }

        // 3. Preserves caller-defined overrides (including empty string) and unrelated vars.
        let custom = serde_json::to_vec(&json!({
            "Image": "alpine",
            "Env": [
                "FOO=bar",
                "HTTP_PROXY=http://custom:8080",
                "no_proxy=corp.local"
            ]
        }))
        .unwrap();
        let plan_custom = sanitize_container_create(&custom, &policy_enabled).unwrap();
        let val_custom: Value = serde_json::from_slice(&plan_custom.rewritten_body).unwrap();
        let env_custom: Vec<&str> = val_custom["Env"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        assert!(env_custom.contains(&"FOO=bar"));
        assert!(env_custom.contains(&"HTTP_PROXY=http://custom:8080"));
        assert!(env_custom.contains(&"no_proxy=corp.local"));
        assert!(!env_custom.contains(&"HTTP_PROXY=http://10.88.0.1:3128"));
        assert!(!env_custom.contains(&"no_proxy=localhost,127.0.0.1,::1,10.88.0.1"));
        assert!(env_custom.contains(&"HTTPS_PROXY=http://10.88.0.1:3128"));
        assert!(env_custom.contains(&"NO_PROXY=localhost,127.0.0.1,::1,10.88.0.1"));

        // 4. Rejects non-array Env cleanly.
        let bad_env = serde_json::to_vec(&json!({ "Image": "alpine", "Env": "FOO=1" })).unwrap();
        assert!(sanitize_container_create(&bad_env, &policy_enabled).is_err());
    }

    #[test]
    fn rejects_lowercase_smuggled_fields_duplicate_keys_and_privileged_capabilities() {
        let policy = DockerCompatPolicy::default();

        let smuggling_payloads: &[&[u8]] = &[
            br#"{"Image":"alpine","hostconfig":{"privileged":true}}"#,
            br#"{"Image":"alpine","hostconfig":{"binds":["/etc:/mnt"]}}"#,
            br#"{"Image":"alpine","HOSTCONFIG":{"mounts":[{"type":"bind","source":"/etc","destination":"/mnt"}]}}"#,
            br#"{"Image":"alpine","HostConfig":{"Privileged":true},"HostConfig":{"Privileged":false}}"#,
            br#"{"Image":"alpine","\u0048ostConfig":{"Privileged":true},"HostConfig":{"Privileged":false}}"#,
            br#"{"Image":"alpine","HostConfig":{},"hostconfig":{"Privileged":true}}"#,
            br#"{"Image":"alpine","HostConfig":{"CapAdd":["SYS_ADMIN"]}}"#,
            br#"{"Image":"alpine","HostConfig":{"Devices":[{"PathOnHost":"/dev/sda"}]}}"#,
            br#"{"Image":"alpine","HostConfig":{"SecurityOpt":["seccomp=unconfined"]}}"#,
        ];

        for raw in smuggling_payloads {
            assert!(
                sanitize_container_create(raw, &policy).is_err(),
                "must reject smuggled/duplicate payload: {}",
                String::from_utf8_lossy(raw)
            );
        }
    }

    #[test]
    fn rejects_unicode_equalfold_keys_ns_modes_masked_paths_and_mutating_route_escapes() {
        let policy = DockerCompatPolicy {
            reaper_socket: ReaperSocketPolicy::Deny,
            container_proxy_http_url: Some("http://10.88.0.1:3128".to_owned()),
        };

        // Go `encoding/json` EqualFold Unicode folding (`\u017f` == 's', `\u212a` == 'k') and
        // Podman-specific namespace/mask/volume/security escapes must all be rejected.
        let forbidden_creates: &[&[u8]] = &[
            br#"{"Image":"alpine","Ho\u017ftConfig":{"Privileged":true}}"#,
            br#"{"Image":"alpine","HostConfig":{"Bind\u017f":["/:/mnt"]}}"#,
            br#"{"Image":"alpine","HostConfig":{"Networ\u212aMode":"host"}}"#,
            br#"{"Image":"alpine","HostConfig":{"PidMode":"ns:/proc/1/ns/pid"}}"#,
            br#"{"Image":"alpine","HostConfig":{"NetworkMode":"slirp4netns:allow_host_loopback=true"}}"#,
            br#"{"Image":"alpine","HostConfig":{"VolumesFrom":["other-ctr"]}}"#,
            br#"{"Image":"alpine","HostConfig":{"MaskedPaths":[]}}"#,
            br#"{"Image":"alpine","HostConfig":{"ReadonlyPaths":[]}}"#,
            br#"{"Image":"alpine","HostConfig":{"Annotations":{"run.oci.keep_original_groups":"1"}}}"#,
            br#"{"Image":"alpine","HostConfig":{"SecurityOpt":["label=type:spc_t"]}}"#,
            br#"{"Image":"alpine","NetworkingConfig":{"EndpointsConfig":{"host":{}}}}"#,
        ];
        for raw in forbidden_creates {
            assert!(
                sanitize_container_create(raw, &policy).is_err(),
                "must reject escape payload: {}",
                String::from_utf8_lossy(raw)
            );
        }

        // Benign `no-new-privileges` and Compose custom networks remain permitted.
        let allowed_create = serde_json::to_vec(&json!({
            "Image": "alpine",
            "HostConfig": {
                "NetworkMode": "my-demo_stack_default",
                "SecurityOpt": ["no-new-privileges:true"]
            },
            "NetworkingConfig": {
                "EndpointsConfig": {
                    "my-demo_stack_default": { "Aliases": ["api"] }
                }
            }
        }))
        .unwrap();
        assert!(sanitize_container_create(&allowed_create, &policy).is_ok());

        // `POST /volumes/create`: block bind DriverOpts, non-local driver, and Unicode keys.
        assert!(sanitize_volume_create(br#"{"Name":"app_data"}"#).is_ok());
        assert!(sanitize_volume_create(
            br#"{"Name":"evil","DriverOpts":{"type":"none","o":"bind","device":"/"}}"#
        )
        .is_err());
        assert!(sanitize_volume_create(
            br#"{"Name":"evil","DriverOpt\u017f":{"device":"/etc"}}"#
        )
        .is_err());

        // `POST /containers/{id}/exec`: block Privileged=true + Unicode keys, inject proxy env.
        assert!(sanitize_exec_create(br#"{"Cmd":["sh"],"Privileged":true}"#, &policy).is_err());
        assert!(
            sanitize_exec_create(br#"{"Cmd":["sh"],"Privilege\u0064":true}"#, &policy).is_err()
        );
        let exec_ok = sanitize_exec_create(br#"{"Cmd":["id"]}"#, &policy).unwrap();
        let exec_val: Value = serde_json::from_slice(&exec_ok).unwrap();
        assert!(exec_val["Env"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v.as_str() == Some("HTTP_PROXY=http://10.88.0.1:3128")));

        // `POST /networks/create`, `POST /networks/{id}/connect`, and `POST /build` query.
        assert!(sanitize_network_create(br#"{"Name":"app_net","Driver":"bridge"}"#).is_ok());
        assert!(sanitize_network_create(br#"{"Name":"host","Driver":"bridge"}"#).is_err());
        assert!(sanitize_network_create(br#"{"Name":"net1","Driver":"macvlan"}"#).is_err());
        assert!(sanitize_network_connect("host", br#"{"Container":"abc"}"#).is_err());
        assert!(sanitize_network_connect("app_net", br#"{"Container":"abc"}"#).is_ok());
        assert!(validate_image_build_query(&[
            ("t".into(), "demo:1".into()),
            ("dockerfile".into(), "docker/Dockerfile".into()),
            ("rm".into(), "true".into()),
            ("version".into(), "1".into()),
            ("networkmode".into(), "bridge".into()),
        ])
        .is_ok());
        assert!(validate_image_build_query(&[("networkmode".into(), "host".into())]).is_err());
        assert!(
            validate_image_build_query(&[("networkmode".into(), "ns:/proc/1/ns/net".into())])
                .is_err()
        );
        for forbidden_param in [
            ("securityopt", "label=disable"),
            ("cgroupparent", "/host.slice"),
            ("capadd", "SYS_ADMIN"),
            ("volume", "/:/host"),
            ("remote", "http://169.254.169.254/ctx.tar"),
            ("outputs", "type=local,dest=/tmp"),
            ("dockerfile", "../etc/passwd"),
        ] {
            assert!(
                validate_image_build_query(&[(
                    forbidden_param.0.into(),
                    forbidden_param.1.into()
                )])
                .is_err(),
                "expected POST /build param {:?} to be rejected",
                forbidden_param
            );
        }

        // Additional HostConfig hardening (#8) and POST /images/create fromSrc checks.
        for forbidden_hc in [
            json!({"Image":"alpine","HostConfig":{"ContainerIDFile":"/host/cid"}}),
            json!({"Image":"alpine","HostConfig":{"OomKillDisable":true}}),
            json!({"Image":"alpine","HostConfig":{"OomScoreAdj":-500}}),
            json!({"Image":"alpine","HostConfig":{"StorageOpt":{"size":"10G"}}}),
            json!({"Image":"alpine","HostConfig":{"LogConfig":{"Type":"syslog"}}}),
            json!({"Image":"alpine","HostConfig":{"LogConfig":{"Type":"json-file","Config":{"path":"/tmp/x"}}}}),
            json!({"Image":"alpine","HostConfig":{"Tmpfs":{"/run":"rw,suid"}}}),
            json!({"Image":"alpine","HostConfig":{"Tmpfs":{"/run":"rw,dev"}}}),
        ] {
            let raw = serde_json::to_vec(&forbidden_hc).unwrap();
            assert!(
                sanitize_container_create(&raw, &policy).is_err(),
                "expected HostConfig rejection for {forbidden_hc}"
            );
        }
        assert!(sanitize_container_create(
            &serde_json::to_vec(&json!({
                "Image": "alpine",
                "HostConfig": {
                    "ContainerIDFile": "",
                    "OomKillDisable": false,
                    "OomScoreAdj": 0,
                    "LogConfig": {"Type": "json-file", "Config": {"max-size": "10m"}},
                    "Tmpfs": {"/tmp": "rw,noexec,nosuid,size=16m"}
                }
            }))
            .unwrap(),
            &policy
        )
        .is_ok());

        assert!(validate_image_create_query(&[("fromImage".into(), "alpine:latest".into())]).is_ok());
        assert!(validate_image_create_query(&[("fromImage".into(), "localhost:5000/org/app:v1".into())]).is_ok());
        assert!(validate_image_create_query(&[("fromImage".into(), "[::1]:5000/org/app:v1".into())]).is_ok());
        assert!(validate_image_create_query(&[
            ("fromImage".into(), "alpine:latest".into()),
            ("changes".into(), "ENV FOO=bar\nLABEL a=b".into()),
            ("quiet".into(), "1".into()),
        ]).is_ok());
        assert!(validate_image_create_query(&[("fromSrc".into(), "-".into())]).is_ok());
        assert!(validate_image_create_query(&[("fromSrc".into(), "https://example.com/img.tar".into())]).is_ok());
        assert!(validate_image_create_query(&[("repo".into(), "my-repo".into()), ("tag".into(), "v1.0".into())]).is_ok());
        assert!(validate_image_create_query(&[("fromSrc".into(), "/etc/passwd".into())]).is_err());
        assert!(
            validate_image_create_query(&[("fromSrc".into(), "http://127.0.0.1/img.tar".into())])
                .is_err()
        );

        // Hardened POST /images/create query & non-canonical fromSrc SSRF bypasses:
        for forbidden_query in [
            vec![("repo".into(), "dir:/etc".into())],
            vec![("fromImage".into(), "tarball:/tmp/x.tar".into())],
            vec![("fromImage".into(), "atomic:quay.io/a/b".into())],
            vec![("fromImage".into(), "zstd:/tmp/x.zst".into())],
            vec![("quiet".into(), "maybe".into())],
            vec![("fromImage".into(), "alpine latest".into())],
            vec![("fromImage".into(), "alpine".into()), ("tlsVerify".into(), "false".into())],
            vec![("tag".into(), "../bad".into())],
            vec![("platform".into(), "linux/amd64:bad".into())],
            vec![("fromSrc".into(), "http://2130706433/img.tar".into())],
            vec![("fromSrc".into(), "http://0x7f000001/img.tar".into())],
            vec![("fromSrc".into(), "http://0177.0.0.1/img.tar".into())],
            vec![("fromSrc".into(), "http://127.1/img.tar".into())],
            vec![("fromSrc".into(), "http://[::ffff:127.0.0.1]/img.tar".into())],
            vec![("fromSrc".into(), "http://[3fff::1]/img.tar".into())],
            vec![("fromSrc".into(), "http://metadata.google.internal/img.tar".into())],
            vec![("fromSrc".into(), "http://singlelabel/img.tar".into())],
            vec![("fromSrc".into(), "http://*.example.com/img.tar".into())],
            vec![("fromSrc".into(), "https://ex ample.com/img.tar".into())],
        ] {
            assert!(
                validate_image_create_query(&forbidden_query).is_err(),
                "expected POST /images/create rejection for {forbidden_query:?}"
            );
        }

        // Hardened Mounts[].TmpfsOptions & HostConfig.Tmpfs option allowlist enforcement:
        for forbidden_tmpfs in [
            json!({"Image":"alpine","HostConfig":{"Tmpfs":{"/run":"rw,mode=4755"}}}),
            json!({"Image":"alpine","HostConfig":{"Tmpfs":{"/run":"rw,rsuid,rdev"}}}),
            json!({"Image":"alpine","HostConfig":{"Tmpfs":{"/run":"rw,remount"}}}),
            json!({"Image":"alpine","HostConfig":{"Tmpfs":{"/run":"idmap"}}}),
            json!({"Image":"alpine","HostConfig":{"Mounts":[{"Type":"tmpfs","Target":"/run","TmpfsOptions":{"Mode":0o4755}}]}}),
            json!({"Image":"alpine","HostConfig":{"Mounts":[{"Type":"tmpfs","Target":"/run","TmpfsOptions":{"SizeBytes":-1}}]}}),
            json!({"Image":"alpine","HostConfig":{"Mounts":[{"Type":"tmpfs","Target":"/run","TmpfsOptions":{"Options":[["suid"]]}}]}}),
            json!({"Image":"alpine","HostConfig":{"Mounts":[{"Type":"tmpfs","Target":"/run","TmpfsOptions":{"Options":[["dev"]]}}]}}),
            json!({"Image":"alpine","HostConfig":{"Mounts":[{"Type":"tmpfs","Target":"/run","TmpfsOptions":{"Options":[["rsuid"]]}}]}}),
            json!({"Image":"alpine","HostConfig":{"Mounts":[{"Type":"tmpfs","Target":"/run","TmpfsOptions":{"Options":[["rdev"]]}}]}}),
            json!({"Image":"alpine","HostConfig":{"Mounts":[{"Type":"tmpfs","Target":"/run","TmpfsOptions":{"Options":[["remount"]]}}]}}),
            json!({"Image":"alpine","HostConfig":{"Mounts":[{"Type":"tmpfs","Target":"/run","TmpfsOptions":{"Options":[["bind"]]}}]}}),
            json!({"Image":"alpine","HostConfig":{"Mounts":[{"Type":"tmpfs","Target":"/run","TmpfsOptions":{"Options":[["rshared"]]}}]}}),
            json!({"Image":"alpine","HostConfig":{"Mounts":[{"Type":"tmpfs","Target":"/run","TmpfsOptions":{"Options":[["mode\n","0755"]]}}]}}),
            json!({"Image":"alpine","HostConfig":{"Mounts":[{"Type":"tmpfs","Target":"/run","TmpfsOptions":{"Options":[["size","10m\r"]]}}]}}),
            json!({"Image":"alpine","HostConfig":{"Mounts":[{"Type":"tmpfs","Target":"/run","TmpfsOptions":{"Options":[["mode","4755"]]}}]}}),
            json!({"Image":"alpine","HostConfig":{"Mounts":[{"Type":"tmpfs","Target":"/run","TmpfsOptions":{"Options":[["rw,suid"]]}}]}}),
            json!({"Image":"alpine","HostConfig":{"Mounts":[{"Type":"tmpfs","Target":"/run","TmpfsOptions":{"UnknownField":1}}]}}),
        ] {
            let raw = serde_json::to_vec(&forbidden_tmpfs).unwrap();
            assert!(
                sanitize_container_create(&raw, &policy).is_err(),
                "expected tmpfs policy rejection for {forbidden_tmpfs}"
            );
        }
        assert!(sanitize_container_create(
            &serde_json::to_vec(&json!({
                "Image": "alpine",
                "HostConfig": {
                    "Tmpfs": {
                        "/tmp": "rw,exec,nosuid,nodev,size=64m,uid=1000,gid=1000,nr_inodes=10k,mode=1777,tmpcopyup"
                    },
                    "Mounts": [{
                        "Type": "tmpfs",
                        "Target": "/run",
                        "TmpfsOptions": {
                            "SizeBytes": 67_108_864,
                            "Mode": 0o1777,
                            "Options": [["noexec"], ["mode", "0755"], ["size", "50%"]]
                        }
                    }]
                }
            }))
            .unwrap(),
            &policy
        )
        .is_ok());
    }
}
