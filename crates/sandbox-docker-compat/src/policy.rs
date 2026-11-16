//! Security policy gate and port normalization for Docker `POST /containers/create` payloads.

use std::collections::BTreeSet;
use std::fmt;

use serde_json::{json, Map, Value};

const DOCKER_SOCKET_PATH: &str = "/var/run/docker.sock";
const DOCKER_SOCKET_WIN_PREFIX_PATH: &str = "//var/run/docker.sock";
const GUEST_PODMAN_SOCKET_PATH: &str = "/run/podman/podman.sock";
const DEFAULT_CONTAINER_NO_PROXY: &str = "localhost,127.0.0.1,::1,10.88.0.1";
const MAX_JSON_NESTING_DEPTH: usize = 128;

const KNOWN_ROOT_FIELDS: &[&str] = &["Volumes", "ExposedPorts", "HostConfig", "Env"];
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
    "PortBindings",
    "PublishAllPorts",
    "CapAdd",
    "Devices",
    "DeviceCgroupRules",
    "SecurityOpt",
];
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
const KNOWN_VOLUME_OPTIONS_FIELDS: &[&str] = &["NoCopy", "Labels", "DriverConfig", "Subpath"];
const KNOWN_DRIVER_CONFIG_FIELDS: &[&str] = &["Name", "Options"];
const KNOWN_PORT_BINDING_FIELDS: &[&str] = &["HostIp", "HostPort"];

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
            let mode = val.as_str().ok_or_else(|| {
                PolicyRejection::new(format!("HostConfig.{field} must be a string"))
            })?;
            if mode.trim().eq_ignore_ascii_case("host") {
                return Err(PolicyRejection::new(format!(
                    "HostConfig.{field}='host' is forbidden inside sandbox isolation"
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

    for list_field in ["Devices", "DeviceCgroupRules", "CapAdd"] {
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

    if let Some(sec_opt) = hc.get("SecurityOpt") {
        if !sec_opt.is_null() {
            let arr = sec_opt.as_array().ok_or_else(|| {
                PolicyRejection::new("HostConfig.SecurityOpt must be a JSON array")
            })?;
            for entry in arr {
                let opt = entry.as_str().ok_or_else(|| {
                    PolicyRejection::new("HostConfig.SecurityOpt entries must be strings")
                })?;
                let lower = opt.to_ascii_lowercase();
                if lower.contains("unconfined") || lower.contains("disable") {
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

fn sanitize_tmpfs_mount(obj: &Map<String, Value>) -> Result<(), PolicyRejection> {
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
                        if !driver_opts.is_null() {
                            let d_map = driver_opts.as_object().ok_or_else(|| {
                                PolicyRejection::new(
                                    "VolumeOptions.DriverConfig.Options must be a JSON object",
                                )
                            })?;
                            for (k, v) in d_map {
                                let key_lower = k.to_ascii_lowercase();
                                let val_str = v.as_str().unwrap_or("");
                                if matches!(key_lower.as_str(), "device" | "o" | "type")
                                    || val_str.contains('/')
                                    || val_str.contains('\\')
                                {
                                    return Err(PolicyRejection::new(format!(
                                        "unsafe VolumeOptions.DriverConfig option '{k}' is forbidden"
                                    )));
                                }
                            }
                        }
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
}
