//! Native multi-container Compose (`compose.yaml` / `docker-compose.yml`) runner for `mini-pod` sandboxes.
//!
//! Parses standard Compose files in pure safe Rust (`yaml-rust2`), builds local `build:` services
//! via [`crate::image_build`], and orchestrates networks, volumes, containers, and Host loopback
//! port-forwarding through `sandboxd`'s owner-only `DockerCompatServer` endpoint — requiring zero
//! Docker or `docker-compose` installation on either the Host or the Guest VM.

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io::Read as _;
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use sandbox_client::{ControlEndpoint, SandboxClient};
use sandbox_core::safe_tar::{
    apply_open_no_follow, is_allowed_macos_root_symlink, is_symlink_or_reparse,
    reject_symlink_or_reparse,
};
use sandbox_core::{ExecRequest, ExecTarget, SandboxError, SandboxId};
use serde_json::{json, Map, Value};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use yaml_rust2::{Yaml, YamlLoader};

use crate::image_build::{
    build_image_in_sandbox, normalize_relative_dockerfile, validate_image_tag, ImageBuildSpec,
};

const LABEL_PROJECT: &str = "com.docker.compose.project";
const LABEL_SERVICE: &str = "com.docker.compose.service";
const LABEL_NETWORK: &str = "com.docker.compose.network";
const LABEL_VOLUME: &str = "com.docker.compose.volume";

const MAX_HTTP_HEADER_BYTES: usize = 64 * 1024;
const MAX_HTTP_LINE_BYTES: usize = 8 * 1024;
const MAX_HTTP_TRAILER_LINES: usize = 128;
const MAX_HTTP_BODY_BYTES: usize = 16 * 1024 * 1024;
const MAX_ENV_FILE_BYTES: usize = 1024 * 1024;

const DEFAULT_COMPOSE_FILENAMES: &[&str] = &[
    "compose.yaml",
    "compose.yml",
    "docker-compose.yml",
    "docker-compose.yaml",
];

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ComposeAction {
    Up {
        file: Option<PathBuf>,
        project: Option<String>,
        build: bool,
        deadline: Duration,
    },
    Ps {
        file: Option<PathBuf>,
        project: Option<String>,
    },
    Logs {
        file: Option<PathBuf>,
        project: Option<String>,
        tail: u32,
        service: Option<String>,
    },
    Down {
        file: Option<PathBuf>,
        project: Option<String>,
        volumes: bool,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ComposeSpec {
    pub project_name: String,
    pub services: BTreeMap<String, ServiceSpec>,
    pub startup_order: Vec<String>,
    pub networks: BTreeMap<String, String>,
    pub volumes: BTreeMap<String, VolumeDecl>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VolumeDecl {
    pub actual_name: String,
    pub external: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServiceSpec {
    pub name: String,
    pub container_name: String,
    pub image: String,
    pub build: Option<ServiceBuildSpec>,
    pub command: Option<Vec<String>>,
    pub entrypoint: Option<Vec<String>>,
    pub env: BTreeMap<String, String>,
    pub working_dir: Option<String>,
    pub user: Option<String>,
    pub hostname: Option<String>,
    pub restart: Option<RestartSpec>,
    pub ports: Vec<ComposePort>,
    pub expose: Vec<u16>,
    pub mounts: Vec<ComposeMount>,
    pub networks: Vec<ServiceNetwork>,
    pub network_mode: Option<String>,
    pub depends_on: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServiceBuildSpec {
    pub context_dir: PathBuf,
    pub dockerfile: Option<String>,
    pub args: Vec<(String, String)>,
    pub target: Option<String>,
    pub no_cache: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RestartSpec {
    pub name: String,
    pub maximum_retry_count: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ComposePort {
    pub host_port: Option<u16>,
    pub container_port: u16,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ComposeMount {
    Volume {
        volume_key: Option<String>,
        source_volume: String,
        target: String,
        read_only: bool,
    },
    Tmpfs {
        target: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServiceNetwork {
    pub network_key: String,
    pub aliases: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StartedServiceSummary {
    pub service: String,
    pub container_name: String,
    pub container_id: String,
    pub image: String,
    pub host_ports: Vec<String>,
}

/// Executes a [`ComposeAction`] against `sandbox_id` via `SandboxClient` and `DockerCompatServer`.
pub async fn execute_compose(
    client: &SandboxClient,
    sandbox_id: &SandboxId,
    json_mode: bool,
    action: ComposeAction,
) -> Result<u8, SandboxError> {
    match action {
        ComposeAction::Up {
            file,
            project,
            build,
            deadline,
        } => {
            let compose_path = resolve_compose_file(file.as_deref())?;
            let spec = load_compose_spec_from_path(&compose_path, project.as_deref())?;
            let started =
                compose_up_in_sandbox(client, sandbox_id, &spec, build, deadline, !json_mode)
                    .await?;
            if json_mode {
                let items: Vec<Value> = started
                    .iter()
                    .map(|s| {
                        json!({
                            "service": s.service,
                            "container_name": s.container_name,
                            "container_id": s.container_id,
                            "image": s.image,
                            "host_ports": s.host_ports,
                        })
                    })
                    .collect();
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "project": spec.project_name,
                        "services": items,
                    }))
                    .unwrap_or_default()
                );
            } else {
                println!(
                    "compose project '{}' up ({} service(s)):",
                    spec.project_name,
                    started.len()
                );
                for s in &started {
                    let ports = if s.host_ports.is_empty() {
                        "-".to_owned()
                    } else {
                        s.host_ports.join(", ")
                    };
                    println!(
                        "  {:<18} {:<26} {:<24} ports={}",
                        s.service, s.container_name, s.image, ports
                    );
                }
            }
            Ok(0)
        }
        ComposeAction::Ps { file, project } => {
            let project_name = resolve_project_name_for_query(file.as_deref(), project.as_deref())?;
            let docker_uri = client.enable_docker_compat(sandbox_id, false).await?;
            let docker_ep = ControlEndpoint::parse(&docker_uri)?;
            let rows = list_project_containers(&docker_ep, &project_name).await?;
            if json_mode {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "project": project_name,
                        "containers": rows,
                    }))
                    .unwrap_or_default()
                );
            } else if rows.is_empty() {
                println!("no containers found for compose project '{project_name}'");
            } else {
                println!(
                    "{:<16} {:<24} {:<24} {:<12} PORTS",
                    "SERVICE", "CONTAINER", "IMAGE", "STATE"
                );
                for row in &rows {
                    println!(
                        "{:<16} {:<24} {:<24} {:<12} {}",
                        row["service"].as_str().unwrap_or("-"),
                        row["name"].as_str().unwrap_or("-"),
                        row["image"].as_str().unwrap_or("-"),
                        row["state"].as_str().unwrap_or("-"),
                        row["ports"].as_str().unwrap_or("-"),
                    );
                }
            }
            Ok(0)
        }
        ComposeAction::Logs {
            file,
            project,
            tail,
            service,
        } => {
            let project_name = resolve_project_name_for_query(file.as_deref(), project.as_deref())?;
            let docker_uri = client.enable_docker_compat(sandbox_id, false).await?;
            let docker_ep = ControlEndpoint::parse(&docker_uri)?;
            let rows = list_project_containers(&docker_ep, &project_name).await?;
            let mut logs_json = Vec::new();
            let tail_str = tail.to_string();

            for row in rows {
                let svc = row["service"].as_str().unwrap_or("").to_owned();
                if let Some(ref wanted) = service {
                    if &svc != wanted {
                        continue;
                    }
                }
                let ctr_id = row["id"].as_str().unwrap_or("").to_owned();
                if ctr_id.is_empty() {
                    continue;
                }
                let req = ExecRequest {
                    target: ExecTarget::Guest,
                    argv: vec![
                        "/usr/bin/podman".to_owned(),
                        "logs".to_owned(),
                        "--tail".to_owned(),
                        tail_str.clone(),
                        "--".to_owned(),
                        ctr_id.clone(),
                    ],
                    env: BTreeMap::new(),
                    cwd: None,
                    user: None,
                    deadline: Duration::from_secs(30),
                    stdout_budget_bytes: 2 * 1024 * 1024,
                    stderr_budget_bytes: 2 * 1024 * 1024,
                };
                let out = client.exec_collect(sandbox_id, req).await?;
                let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
                let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
                if json_mode {
                    logs_json.push(json!({
                        "service": svc,
                        "container_id": ctr_id,
                        "stdout": stdout,
                        "stderr": stderr,
                    }));
                } else {
                    for line in stdout.lines() {
                        println!("[{svc}] {line}");
                    }
                    for line in stderr.lines() {
                        eprintln!("[{svc}] {line}");
                    }
                }
            }

            if json_mode {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "project": project_name,
                        "logs": logs_json,
                    }))
                    .unwrap_or_default()
                );
            }
            Ok(0)
        }
        ComposeAction::Down {
            file,
            project,
            volumes,
        } => {
            let project_name = resolve_project_name_for_query(file.as_deref(), project.as_deref())?;
            let summary = compose_down_in_sandbox(client, sandbox_id, &project_name, volumes).await?;
            if json_mode {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&summary).unwrap_or_default()
                );
            } else {
                println!(
                    "compose project '{}' down: removed_containers={} removed_networks={} removed_volumes={}",
                    project_name,
                    summary["removed_containers"].as_u64().unwrap_or(0),
                    summary["removed_networks"].as_u64().unwrap_or(0),
                    summary["removed_volumes"].as_u64().unwrap_or(0),
                );
            }
            Ok(0)
        }
    }
}

/// Brings up all services in `spec` inside `sandbox_id` (reusable by CLI and TUI).
pub async fn compose_up_in_sandbox(
    client: &SandboxClient,
    sandbox_id: &SandboxId,
    spec: &ComposeSpec,
    force_build: bool,
    deadline: Duration,
    stream_build_stdio: bool,
) -> Result<Vec<StartedServiceSummary>, SandboxError> {
    // 1. Build any `build:` services when `--build` is set or the target image is absent.
    for svc_name in &spec.startup_order {
        let svc = &spec.services[svc_name];
        if let Some(ref b) = svc.build {
            let should_build = if force_build {
                true
            } else {
                !guest_image_exists(client, sandbox_id, &svc.image).await?
            };
            if should_build {
                let build_spec = ImageBuildSpec {
                    context_dir: b.context_dir.clone(),
                    dockerfile: b.dockerfile.clone(),
                    tags: vec![svc.image.clone()],
                    build_args: b.args.clone(),
                    target: b.target.clone(),
                    no_cache: b.no_cache,
                    output_tar: None,
                    deadline,
                };
                let res =
                    build_image_in_sandbox(client, sandbox_id, build_spec, stream_build_stdio)
                        .await?;
                if res.exit.code != Some(0) || res.exit.timed_out {
                    return Err(SandboxError::Internal(format!(
                        "compose build failed for service '{}' (exit={:?}, timed_out={}): {}",
                        svc.name,
                        res.exit.code,
                        res.exit.timed_out,
                        res.stderr.trim()
                    )));
                }
            }
        } else if !guest_image_exists(client, sandbox_id, &svc.image).await? {
            pull_guest_image(client, sandbox_id, &svc.image, deadline, stream_build_stdio).await?;
        }
    }

    // 2. Bind (or reuse) owner-only DockerCompatServer so published ports forward onto Host 127.0.0.1.
    let docker_uri = client.enable_docker_compat(sandbox_id, false).await?;
    let docker_ep = ControlEndpoint::parse(&docker_uri)?;

    // 3. Ensure project networks exist.
    for (net_key, actual_net_name) in &spec.networks {
        ensure_network(&docker_ep, &spec.project_name, net_key, actual_net_name).await?;
    }

    // 4. Ensure named volumes exist.
    for (vol_key, decl) in &spec.volumes {
        if !decl.external {
            ensure_volume(&docker_ep, &spec.project_name, vol_key, &decl.actual_name).await?;
        }
    }

    // 5. Recreate and start each service in topological dependency order.
    let mut summaries = Vec::with_capacity(spec.startup_order.len());
    for svc_name in &spec.startup_order {
        let svc = &spec.services[svc_name];
        remove_container_if_exists(&docker_ep, &svc.container_name).await?;

        let create_payload = build_container_create_payload(spec, svc);
        let create_path = format!(
            "/containers/create?name={}",
            percent_encode_component(&svc.container_name)
        );
        let (status, body) = docker_json_request(&docker_ep, "POST", &create_path, Some(&create_payload)).await?;
        if status != 201 {
            return Err(docker_http_error(
                &format!("create container '{}'", svc.container_name),
                status,
                &body,
            ));
        }
        let created_json: Value = serde_json::from_slice(&body).map_err(|err| {
            SandboxError::Transport(format!("invalid create container JSON response: {err}"))
        })?;
        let container_id = created_json["Id"]
            .as_str()
            .ok_or_else(|| {
                SandboxError::Transport("create container response missing 'Id'".to_owned())
            })?
            .to_owned();

        // Attach any secondary networks (`idx >= 1`) before starting the container.
        for extra_net in svc.networks.iter().skip(1) {
            let actual_net = spec
                .networks
                .get(&extra_net.network_key)
                .cloned()
                .unwrap_or_else(|| format!("{}_{}", spec.project_name, extra_net.network_key));
            let connect_body = json!({
                "Container": container_id,
                "EndpointConfig": {
                    "Aliases": extra_net.aliases,
                }
            });
            let connect_path = format!(
                "/networks/{}/connect",
                percent_encode_component(&actual_net)
            );
            let (c_status, c_body) =
                docker_json_request(&docker_ep, "POST", &connect_path, Some(&connect_body)).await?;
            if !(200..300).contains(&c_status) {
                return Err(docker_http_error(
                    &format!("connect network '{actual_net}'"),
                    c_status,
                    &c_body,
                ));
            }
        }

        let start_path = format!(
            "/containers/{}/start",
            percent_encode_component(&container_id)
        );
        let (start_status, start_body) =
            docker_json_request(&docker_ep, "POST", &start_path, None).await?;
        if start_status != 204 && start_status != 304 {
            return Err(docker_http_error(
                &format!("start container '{}'", svc.container_name),
                start_status,
                &start_body,
            ));
        }

        let inspect_path = format!(
            "/containers/{}/json",
            percent_encode_component(&container_id)
        );
        let (ins_status, ins_body) =
            docker_json_request(&docker_ep, "GET", &inspect_path, None).await?;
        let host_ports = if ins_status == 200 {
            if let Ok(ins_val) = serde_json::from_slice::<Value>(&ins_body) {
                extract_inspected_host_ports(&ins_val)
            } else {
                Vec::new()
            }
        } else {
            Vec::new()
        };

        summaries.push(StartedServiceSummary {
            service: svc.name.clone(),
            container_name: svc.container_name.clone(),
            container_id: container_id.chars().take(12).collect(),
            image: svc.image.clone(),
            host_ports,
        });
    }

    Ok(summaries)
}

/// Stops and deletes all containers, networks, and (optionally) volumes belonging to `project_name`.
pub async fn compose_down_in_sandbox(
    client: &SandboxClient,
    sandbox_id: &SandboxId,
    project_name: &str,
    remove_volumes: bool,
) -> Result<Value, SandboxError> {
    let docker_uri = client.enable_docker_compat(sandbox_id, false).await?;
    let docker_ep = ControlEndpoint::parse(&docker_uri)?;

    let containers = list_project_containers(&docker_ep, project_name).await?;
    let mut removed_containers = 0u64;
    // Tear down in reverse order.
    for row in containers.iter().rev() {
        if let Some(id) = row["id"].as_str() {
            let stop_path = format!("/containers/{}/stop?t=3", percent_encode_component(id));
            let _ = docker_json_request(&docker_ep, "POST", &stop_path, None).await?;
            let del_path = format!("/containers/{}?force=true", percent_encode_component(id));
            let (st, _) = docker_json_request(&docker_ep, "DELETE", &del_path, None).await?;
            if (200..300).contains(&st) || st == 404 {
                removed_containers += 1;
            }
        }
    }

    let mut removed_networks = 0u64;
    let (net_st, net_body) = docker_json_request(&docker_ep, "GET", "/networks", None).await?;
    if net_st == 200 {
        if let Ok(Value::Array(nets)) = serde_json::from_slice::<Value>(&net_body) {
            for net in nets {
                let matches_label = net["Labels"][LABEL_PROJECT].as_str() == Some(project_name);
                if matches_label {
                    if let Some(name) = net["Name"].as_str() {
                        let path = format!("/networks/{}", percent_encode_component(name));
                        let (st, _) = docker_json_request(&docker_ep, "DELETE", &path, None).await?;
                        if (200..300).contains(&st) {
                            removed_networks += 1;
                        }
                    }
                }
            }
        }
    }

    let mut removed_volumes = 0u64;
    if remove_volumes {
        let (vol_st, vol_body) = docker_json_request(&docker_ep, "GET", "/volumes", None).await?;
        if vol_st == 200 {
            if let Ok(parsed) = serde_json::from_slice::<Value>(&vol_body) {
                if let Some(vols) = parsed["Volumes"].as_array() {
                    for vol in vols {
                        let matches_label =
                            vol["Labels"][LABEL_PROJECT].as_str() == Some(project_name);
                        if matches_label {
                            if let Some(name) = vol["Name"].as_str() {
                                let path = format!("/volumes/{}", percent_encode_component(name));
                                let (st, _) =
                                    docker_json_request(&docker_ep, "DELETE", &path, None).await?;
                                if (200..300).contains(&st) {
                                    removed_volumes += 1;
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(json!({
        "project": project_name,
        "removed_containers": removed_containers,
        "removed_networks": removed_networks,
        "removed_volumes": removed_volumes,
    }))
}

fn resolve_compose_file(explicit: Option<&Path>) -> Result<PathBuf, SandboxError> {
    if let Some(path) = explicit {
        let meta = fs::symlink_metadata(path).map_err(|err| {
            SandboxError::InvalidSpec(format!(
                "cannot access compose file '{}': {err}",
                path.display()
            ))
        })?;
        if is_symlink_or_reparse(&meta) || !meta.is_file() {
            return Err(SandboxError::PolicyViolation(format!(
                "compose file '{}' must be a regular non-symlink file",
                path.display()
            )));
        }
        return Ok(path.to_path_buf());
    }

    let cwd = std::env::current_dir().map_err(|err| {
        SandboxError::InvalidSpec(format!("cannot determine current working directory: {err}"))
    })?;
    for candidate_name in DEFAULT_COMPOSE_FILENAMES {
        let candidate = cwd.join(candidate_name);
        if let Ok(meta) = fs::symlink_metadata(&candidate) {
            if !is_symlink_or_reparse(&meta) && meta.is_file() {
                return Ok(candidate);
            }
        }
    }
    Err(SandboxError::InvalidSpec(
        "no compose file found (expected compose.yaml, compose.yml, or docker-compose.yml; or pass -f <file>)"
            .to_owned(),
    ))
}

fn resolve_project_name_for_query(
    file: Option<&Path>,
    explicit_project: Option<&str>,
) -> Result<String, SandboxError> {
    if let Some(proj) = explicit_project {
        return sanitize_project_name(proj);
    }
    let compose_path = resolve_compose_file(file)?;
    let spec = load_compose_spec_from_path(&compose_path, None)?;
    Ok(spec.project_name)
}

/// Reads and validates a Compose YAML file from disk.
pub fn load_compose_spec_from_path(
    compose_path: &Path,
    project_override: Option<&str>,
) -> Result<ComposeSpec, SandboxError> {
    let meta = fs::symlink_metadata(compose_path).map_err(|err| {
        SandboxError::InvalidSpec(format!(
            "cannot inspect compose file '{}': {err}",
            compose_path.display()
        ))
    })?;
    if is_symlink_or_reparse(&meta) || !meta.is_file() {
        return Err(SandboxError::PolicyViolation(format!(
            "compose file '{}' must be a regular non-symlink file",
            compose_path.display()
        )));
    }
    let raw = fs::read_to_string(compose_path).map_err(|err| {
        SandboxError::InvalidSpec(format!(
            "failed reading compose file '{}': {err}",
            compose_path.display()
        ))
    })?;
    let base_dir = compose_path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map(Path::to_path_buf)
        .or_else(|| std::env::current_dir().ok())
        .unwrap_or_else(|| PathBuf::from("."));
    parse_compose_yaml(&raw, &base_dir, project_override)
}

/// Pure Compose YAML parser (unit-testable without disk fixtures unless `env_file` is used).
pub fn parse_compose_yaml(
    yaml_text: &str,
    base_dir: &Path,
    project_override: Option<&str>,
) -> Result<ComposeSpec, SandboxError> {
    let docs = YamlLoader::load_from_str(yaml_text.trim_start_matches('\u{feff}'))
        .map_err(|err| SandboxError::InvalidSpec(format!("invalid Compose YAML syntax: {err}")))?;
    let Some(root) = docs.into_iter().next() else {
        return Err(SandboxError::InvalidSpec(
            "Compose YAML document is empty".to_owned(),
        ));
    };
    let root_map = root.as_hash().ok_or_else(|| {
        SandboxError::InvalidSpec("Compose root document must be a YAML mapping".to_owned())
    })?;

    let inferred_dir_name = base_dir
        .canonicalize()
        .ok()
        .and_then(|p| p.file_name().and_then(|n| n.to_str()).map(str::to_owned))
        .or_else(|| {
            base_dir
                .file_name()
                .and_then(|n| n.to_str())
                .map(str::to_owned)
        })
        .unwrap_or_else(|| "app".to_owned());

    let project_name = if let Some(ov) = project_override {
        sanitize_project_name(ov)?
    } else if let Some(yaml_name) = map_get_str(root_map, "name")? {
        sanitize_project_name(&yaml_name)?
    } else {
        sanitize_project_name(&inferred_dir_name).unwrap_or_else(|_| "app".to_owned())
    };

    let mut declared_networks: BTreeMap<String, String> = BTreeMap::new();
    if let Some(nets_yaml) = map_get(root_map, "networks") {
        if !nets_yaml.is_null() {
            let nets_map = nets_yaml.as_hash().ok_or_else(|| {
                SandboxError::InvalidSpec("top-level 'networks' must be a mapping".to_owned())
            })?;
            for (k, v) in nets_map {
                let net_key = yaml_key_str(k, "networks")?;
                validate_safe_identifier(&net_key, "network key")?;
                let custom_name = v
                    .as_hash()
                    .and_then(|h| map_get_str(h, "name").ok().flatten());
                let actual = match custom_name {
                    Some(n) => {
                        validate_safe_identifier(&n, "network name")?;
                        n
                    }
                    None => format!("{project_name}_{net_key}"),
                };
                declared_networks.insert(net_key, actual);
            }
        }
    }

    let mut declared_volumes: BTreeMap<String, VolumeDecl> = BTreeMap::new();
    if let Some(vols_yaml) = map_get(root_map, "volumes") {
        if !vols_yaml.is_null() {
            let vols_map = vols_yaml.as_hash().ok_or_else(|| {
                SandboxError::InvalidSpec("top-level 'volumes' must be a mapping".to_owned())
            })?;
            for (k, v) in vols_map {
                let vol_key = yaml_key_str(k, "volumes")?;
                validate_safe_identifier(&vol_key, "volume key")?;
                let mut external = false;
                let mut custom_name = None;
                if let Some(vh) = v.as_hash() {
                    if let Some(ext_val) = map_get(vh, "external") {
                        external = ext_val.as_bool().unwrap_or(false);
                    }
                    custom_name = map_get_str(vh, "name")?;
                }
                let actual_name = match custom_name {
                    Some(n) => {
                        validate_safe_identifier(&n, "volume name")?;
                        n
                    }
                    None if external => vol_key.clone(),
                    None => format!("{project_name}_{vol_key}"),
                };
                declared_volumes.insert(
                    vol_key,
                    VolumeDecl {
                        actual_name,
                        external,
                    },
                );
            }
        }
    }

    let services_yaml = map_get(root_map, "services").ok_or_else(|| {
        SandboxError::InvalidSpec("Compose file missing required 'services' mapping".to_owned())
    })?;
    let services_map = services_yaml.as_hash().ok_or_else(|| {
        SandboxError::InvalidSpec("'services' must be a YAML mapping".to_owned())
    })?;
    if services_map.is_empty() {
        return Err(SandboxError::InvalidSpec(
            "'services' mapping must define at least one service".to_owned(),
        ));
    }

    let mut services = BTreeMap::new();
    let mut seen_container_names = BTreeSet::new();
    let mut needs_default_network = false;

    for (raw_svc_key, svc_val) in services_map {
        let svc_name = yaml_key_str(raw_svc_key, "services")?;
        validate_safe_identifier(&svc_name, "service name")?;
        if services.contains_key(&svc_name) {
            return Err(SandboxError::InvalidSpec(format!(
                "duplicate service '{svc_name}'"
            )));
        }
        let svc_hash = svc_val.as_hash().ok_or_else(|| {
            SandboxError::InvalidSpec(format!("service '{svc_name}' must be a YAML mapping"))
        })?;

        if let Some(Yaml::Boolean(true)) = map_get(svc_hash, "privileged") {
            return Err(SandboxError::PolicyViolation(format!(
                "service '{svc_name}' sets privileged=true, which is forbidden inside sandbox isolation"
            )));
        }
        let network_mode = if let Some(net_mode) = map_get_str(svc_hash, "network_mode")? {
            let trimmed = net_mode.trim();
            if trimmed.is_empty() {
                None
            } else if trimmed.eq_ignore_ascii_case("host") {
                return Err(SandboxError::PolicyViolation(format!(
                    "service '{svc_name}' sets network_mode='host', which is forbidden inside sandbox isolation"
                )));
            } else if trimmed.eq_ignore_ascii_case("none")
                || trimmed.eq_ignore_ascii_case("bridge")
                || trimmed.eq_ignore_ascii_case("default")
            {
                Some(trimmed.to_ascii_lowercase())
            } else {
                return Err(SandboxError::InvalidSpec(format!(
                    "service '{svc_name}' sets unsupported network_mode '{net_mode}' (expected 'none', 'bridge', or 'default')"
                )));
            }
        } else {
            None
        };
        if matches!(network_mode.as_deref(), Some("none"))
            && map_get(svc_hash, "networks").is_some_and(|v| !v.is_null())
        {
            return Err(SandboxError::InvalidSpec(format!(
                "service '{svc_name}' cannot specify both network_mode='none' and 'networks'"
            )));
        }

        let build = parse_service_build(svc_hash, base_dir, &svc_name)?;
        let image = match map_get_str(svc_hash, "image")? {
            Some(img) => {
                validate_image_tag(&img)?;
                img
            }
            None if build.is_some() => format!("{project_name}-{svc_name}:latest"),
            None => {
                return Err(SandboxError::InvalidSpec(format!(
                    "service '{svc_name}' must specify either 'image' or 'build'"
                )));
            }
        };

        let container_name = match map_get_str(svc_hash, "container_name")? {
            Some(cn) => {
                validate_safe_identifier(&cn, "container_name")?;
                cn
            }
            None => format!("{project_name}-{svc_name}-1"),
        };
        if !seen_container_names.insert(container_name.clone()) {
            return Err(SandboxError::InvalidSpec(format!(
                "duplicate container_name '{container_name}' across services"
            )));
        }

        let command = parse_command_or_entrypoint(svc_hash, "command", &svc_name)?;
        let entrypoint = parse_command_or_entrypoint(svc_hash, "entrypoint", &svc_name)?;
        let env = parse_service_env(svc_hash, base_dir, &svc_name)?;
        let working_dir = map_get_str(svc_hash, "working_dir")?;
        let user = map_get_str(svc_hash, "user")?;
        let hostname = map_get_str(svc_hash, "hostname")?;
        let restart = parse_restart_policy(svc_hash, &svc_name)?;
        let ports = parse_service_ports(svc_hash, &svc_name)?;
        let expose = parse_service_expose(svc_hash, &svc_name)?;
        let mounts = parse_service_mounts(
            svc_hash,
            &svc_name,
            &project_name,
            &mut declared_volumes,
        )?;
        let networks = if matches!(network_mode.as_deref(), Some("none")) {
            Vec::new()
        } else {
            parse_service_networks(svc_hash, &svc_name, &declared_networks)?
        };
        if networks.iter().any(|n| n.network_key == "default") {
            needs_default_network = true;
        }
        let depends_on = parse_depends_on(svc_hash, &svc_name)?;

        services.insert(
            svc_name.clone(),
            ServiceSpec {
                name: svc_name,
                container_name,
                image,
                build,
                command,
                entrypoint,
                env,
                working_dir,
                user,
                hostname,
                restart,
                ports,
                expose,
                mounts,
                networks,
                network_mode,
                depends_on,
            },
        );
    }

    if needs_default_network && !declared_networks.contains_key("default") {
        declared_networks.insert("default".to_owned(), format!("{project_name}_default"));
    }

    let startup_order = topological_sort_services(&services)?;

    Ok(ComposeSpec {
        project_name,
        services,
        startup_order,
        networks: declared_networks,
        volumes: declared_volumes,
    })
}

fn sanitize_project_name(raw: &str) -> Result<String, SandboxError> {
    let cleaned: String = raw
        .trim()
        .chars()
        .map(|c| c.to_ascii_lowercase())
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
        .collect();
    let trimmed = cleaned.trim_start_matches(['-', '_']).to_owned();
    if trimmed.is_empty() {
        return Err(SandboxError::InvalidSpec(format!(
            "invalid Compose project name '{raw}'"
        )));
    }
    Ok(trimmed)
}

pub(crate) fn validate_safe_identifier(val: &str, label: &str) -> Result<(), SandboxError> {
    let mut chars = val.chars();
    let Some(first) = chars.next() else {
        return Err(SandboxError::InvalidSpec(format!("{label} cannot be empty")));
    };
    if !first.is_ascii_alphanumeric()
        || !chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
    {
        return Err(SandboxError::InvalidSpec(format!(
            "invalid {label} '{val}' (must match [a-zA-Z0-9][a-zA-Z0-9_.-]*)"
        )));
    }
    Ok(())
}

fn map_get<'a>(map: &'a yaml_rust2::yaml::Hash, key: &str) -> Option<&'a Yaml> {
    map.get(&Yaml::String(key.to_owned()))
}

fn yaml_key_str(y: &Yaml, ctx: &str) -> Result<String, SandboxError> {
    yaml_scalar_to_string(y).ok_or_else(|| {
        SandboxError::InvalidSpec(format!("expected string key in '{ctx}' mapping"))
    })
}

fn yaml_scalar_to_string(y: &Yaml) -> Option<String> {
    match y {
        Yaml::String(s) => Some(s.clone()),
        Yaml::Integer(i) => Some(i.to_string()),
        Yaml::Real(r) => Some(r.clone()),
        Yaml::Boolean(b) => Some(b.to_string()),
        _ => None,
    }
}

fn map_get_str(map: &yaml_rust2::yaml::Hash, key: &str) -> Result<Option<String>, SandboxError> {
    let Some(val) = map_get(map, key) else {
        return Ok(None);
    };
    if val.is_null() {
        return Ok(None);
    }
    yaml_scalar_to_string(val)
        .map(Some)
        .ok_or_else(|| SandboxError::InvalidSpec(format!("field '{key}' must be a string")))
}

fn parse_service_build(
    svc_hash: &yaml_rust2::yaml::Hash,
    base_dir: &Path,
    svc_name: &str,
) -> Result<Option<ServiceBuildSpec>, SandboxError> {
    let Some(b_val) = map_get(svc_hash, "build") else {
        return Ok(None);
    };
    if b_val.is_null() {
        return Ok(None);
    }
    if let Some(ctx_rel) = b_val.as_str() {
        return Ok(Some(ServiceBuildSpec {
            context_dir: resolve_confined_project_subpath(
                base_dir,
                ctx_rel,
                &format!("service '{svc_name}' build.context"),
            )?,
            dockerfile: None,
            args: Vec::new(),
            target: None,
            no_cache: false,
        }));
    }
    let bh = b_val.as_hash().ok_or_else(|| {
        SandboxError::InvalidSpec(format!(
            "service '{svc_name}' build must be a path string or mapping"
        ))
    })?;
    let ctx_rel = map_get_str(bh, "context")?.unwrap_or_else(|| ".".to_owned());
    let context_dir = resolve_confined_project_subpath(
        base_dir,
        &ctx_rel,
        &format!("service '{svc_name}' build.context"),
    )?;
    let dockerfile = match map_get_str(bh, "dockerfile")? {
        Some(df_raw) => {
            let norm = normalize_relative_dockerfile(&df_raw)?;
            let _ = resolve_confined_project_subpath(
                &context_dir,
                &norm,
                &format!("service '{svc_name}' build.dockerfile"),
            )?;
            Some(norm)
        }
        None => None,
    };
    let target = map_get_str(bh, "target")?;
    let no_cache = map_get(bh, "no_cache")
        .and_then(Yaml::as_bool)
        .unwrap_or(false);
    let mut args = Vec::new();
    if let Some(args_val) = map_get(bh, "args") {
        let map = parse_key_val_collection(args_val, &format!("services.{svc_name}.build.args"))?;
        args.extend(map);
    }
    Ok(Some(ServiceBuildSpec {
        context_dir,
        dockerfile,
        args,
        target,
        no_cache,
    }))
}

fn resolve_confined_project_subpath(
    base_dir: &Path,
    raw: &str,
    label: &str,
) -> Result<PathBuf, SandboxError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.contains('\0') {
        return Err(SandboxError::InvalidSpec(format!(
            "{label} must not be empty or contain NUL bytes"
        )));
    }
    let raw_bytes = trimmed.as_bytes();
    let has_drive_prefix =
        raw_bytes.len() >= 2 && raw_bytes[0].is_ascii_alphabetic() && raw_bytes[1] == b':';
    if has_drive_prefix || trimmed.starts_with('/') || trimmed.starts_with('\\') {
        return Err(SandboxError::PolicyViolation(format!(
            "{label} '{trimmed}' must be a relative path confined inside project directory '{}'",
            base_dir.display()
        )));
    }

    let unified = trimmed.replace('\\', "/");
    let p = Path::new(&unified);
    if p.is_absolute() {
        return Err(SandboxError::PolicyViolation(format!(
            "{label} '{trimmed}' must not be an absolute path",
        )));
    }

    let mut rel_stack: Vec<OsString> = Vec::new();
    for comp in p.components() {
        match comp {
            Component::CurDir => {}
            Component::Normal(part) => rel_stack.push(part.to_os_string()),
            Component::ParentDir => {
                if rel_stack.pop().is_none() {
                    return Err(SandboxError::PolicyViolation(format!(
                        "{label} '{trimmed}' escapes Compose project directory '{}'",
                        base_dir.display()
                    )));
                }
            }
            Component::Prefix(_) | Component::RootDir => {
                return Err(SandboxError::PolicyViolation(format!(
                    "{label} '{trimmed}' must stay inside Compose project directory '{}'",
                    base_dir.display()
                )));
            }
        }
    }

    if let Ok(base_meta) = fs::symlink_metadata(base_dir) {
        if !is_allowed_macos_root_symlink(base_dir, &base_meta) {
            reject_symlink_or_reparse(base_dir, &base_meta)?;
        }
    }
    let mut cur = base_dir.to_path_buf();
    for part in rel_stack {
        cur.push(part);
        if let Ok(meta) = fs::symlink_metadata(&cur) {
            reject_symlink_or_reparse(&cur, &meta)?;
        }
    }
    Ok(cur)
}

fn parse_command_or_entrypoint(
    svc_hash: &yaml_rust2::yaml::Hash,
    field: &str,
    svc_name: &str,
) -> Result<Option<Vec<String>>, SandboxError> {
    let Some(val) = map_get(svc_hash, field) else {
        return Ok(None);
    };
    if val.is_null() {
        return Ok(None);
    }
    if let Some(s) = val.as_str() {
        let words = split_shell_words(s)?;
        return Ok((!words.is_empty()).then_some(words));
    }
    if let Some(arr) = val.as_vec() {
        let mut out = Vec::with_capacity(arr.len());
        for item in arr {
            let s = yaml_scalar_to_string(item).ok_or_else(|| {
                SandboxError::InvalidSpec(format!(
                    "service '{svc_name}' {field} list items must be scalars"
                ))
            })?;
            out.push(s);
        }
        return Ok(Some(out));
    }
    Err(SandboxError::InvalidSpec(format!(
        "service '{svc_name}' {field} must be a string or list"
    )))
}

/// Minimal POSIX-style word splitter for Compose string `command:` / `entrypoint:` fields.
pub fn split_shell_words(input: &str) -> Result<Vec<String>, SandboxError> {
    let mut words = Vec::new();
    let mut cur = String::new();
    let mut in_token = false;
    let mut chars = input.chars().peekable();
    let mut quote: Option<char> = None;

    while let Some(ch) = chars.next() {
        match quote {
            Some('\'') => {
                if ch == '\'' {
                    quote = None;
                } else {
                    cur.push(ch);
                }
            }
            Some('"') => match ch {
                '"' => quote = None,
                '\\' => {
                    if let Some(&next) = chars.peek() {
                        if matches!(next, '"' | '\\' | '$' | '`') {
                            cur.push(chars.next().unwrap());
                        } else {
                            cur.push('\\');
                        }
                    } else {
                        cur.push('\\');
                    }
                }
                other => cur.push(other),
            },
            Some(_) => unreachable!(),
            None => match ch {
                '\'' | '"' => {
                    in_token = true;
                    quote = Some(ch);
                }
                '\\' => {
                    in_token = true;
                    if let Some(next) = chars.next() {
                        cur.push(next);
                    }
                }
                c if c.is_whitespace() => {
                    if in_token {
                        words.push(std::mem::take(&mut cur));
                        in_token = false;
                    }
                }
                other => {
                    in_token = true;
                    cur.push(other);
                }
            },
        }
    }

    if quote.is_some() {
        return Err(SandboxError::InvalidSpec(format!(
            "unterminated quote in command string '{input}'"
        )));
    }
    if in_token {
        words.push(cur);
    }
    Ok(words)
}

fn parse_service_env(
    svc_hash: &yaml_rust2::yaml::Hash,
    base_dir: &Path,
    svc_name: &str,
) -> Result<BTreeMap<String, String>, SandboxError> {
    let mut env = BTreeMap::new();

    if let Some(ef_val) = map_get(svc_hash, "env_file") {
        let mut files = Vec::new();
        if let Some(s) = ef_val.as_str() {
            files.push(s.to_owned());
        } else if let Some(arr) = ef_val.as_vec() {
            for item in arr {
                if let Some(s) = item.as_str() {
                    files.push(s.to_owned());
                } else if let Some(h) = item.as_hash() {
                    if let Some(p) = map_get_str(h, "path")? {
                        files.push(p);
                    }
                }
            }
        }
        for rel in files {
            let path = resolve_confined_project_subpath(
                base_dir,
                &rel,
                &format!("service '{svc_name}' env_file"),
            )?;
            let content = read_confined_env_file(&path, svc_name)?;
            for (line_no, raw_line) in content.trim_start_matches('\u{feff}').lines().enumerate() {
                if raw_line.contains('\0') {
                    return Err(SandboxError::InvalidSpec(format!(
                        "env_file {}:{} contains forbidden NUL byte",
                        path.display(),
                        line_no + 1
                    )));
                }
                let trimmed = raw_line.trim();
                if trimmed.is_empty() || trimmed.starts_with('#') {
                    continue;
                }
                let stripped = trimmed.strip_prefix("export ").unwrap_or(trimmed).trim();
                let Some((k, v)) = stripped.split_once('=') else {
                    return Err(SandboxError::InvalidSpec(format!(
                        "invalid env_file entry at {}:{}: expected KEY=VALUE",
                        path.display(),
                        line_no + 1
                    )));
                };
                let key = k.trim();
                if key.is_empty() || key.contains(|c: char| c.is_whitespace() || c == '=') {
                    return Err(SandboxError::InvalidSpec(format!(
                        "invalid env_file key at {}:{}",
                        path.display(),
                        line_no + 1
                    )));
                }
                let v_trimmed = v.trim();
                let val = if v_trimmed.len() >= 2
                    && ((v_trimmed.starts_with('"') && v_trimmed.ends_with('"'))
                        || (v_trimmed.starts_with('\'') && v_trimmed.ends_with('\'')))
                {
                    &v_trimmed[1..v_trimmed.len() - 1]
                } else {
                    v_trimmed
                };
                env.insert(key.to_owned(), val.to_owned());
            }
        }
    }

    if let Some(env_val) = map_get(svc_hash, "environment") {
        for (k, v) in parse_key_val_collection(env_val, &format!("services.{svc_name}.environment"))? {
            env.insert(k, v);
        }
    }

    Ok(env)
}

fn read_confined_env_file(path: &Path, svc_name: &str) -> Result<String, SandboxError> {
    let meta = fs::symlink_metadata(path).map_err(|err| {
        SandboxError::InvalidSpec(format!(
            "service '{svc_name}' env_file '{}' cannot be accessed: {err}",
            path.display()
        ))
    })?;
    if is_symlink_or_reparse(&meta) || !meta.is_file() {
        return Err(SandboxError::PolicyViolation(format!(
            "service '{svc_name}' env_file '{}' must be a regular non-symlink file",
            path.display()
        )));
    }
    let mut opts = OpenOptions::new();
    opts.read(true);
    apply_open_no_follow(&mut opts);
    let mut file = opts.open(path).map_err(|err| {
        SandboxError::InvalidSpec(format!(
            "service '{svc_name}' env_file '{}' cannot be opened: {err}",
            path.display()
        ))
    })?;
    let open_meta = file.metadata().map_err(|err| {
        SandboxError::InvalidSpec(format!(
            "service '{svc_name}' env_file '{}' cannot be inspected: {err}",
            path.display()
        ))
    })?;
    if is_symlink_or_reparse(&open_meta) || !open_meta.file_type().is_file() {
        return Err(SandboxError::PolicyViolation(format!(
            "service '{svc_name}' env_file '{}' must be a regular non-symlink file",
            path.display()
        )));
    }
    let mut buf = Vec::new();
    (&mut file)
        .take((MAX_ENV_FILE_BYTES + 1) as u64)
        .read_to_end(&mut buf)
        .map_err(|err| {
            SandboxError::InvalidSpec(format!("failed reading env_file '{}': {err}", path.display()))
        })?;
    if buf.len() > MAX_ENV_FILE_BYTES {
        return Err(SandboxError::BudgetExceeded(format!(
            "service '{svc_name}' env_file '{}' exceeds {} bytes",
            path.display(),
            MAX_ENV_FILE_BYTES
        )));
    }
    String::from_utf8(buf).map_err(|err| {
        SandboxError::InvalidSpec(format!(
            "service '{svc_name}' env_file '{}' is not valid UTF-8: {err}",
            path.display()
        ))
    })
}

fn parse_key_val_collection(
    val: &Yaml,
    ctx: &str,
) -> Result<BTreeMap<String, String>, SandboxError> {
    let mut out = BTreeMap::new();
    if val.is_null() {
        return Ok(out);
    }
    if let Some(hash) = val.as_hash() {
        for (k, v) in hash {
            let key = yaml_key_str(k, ctx)?;
            if key.is_empty() || key.contains('=') || key.contains('\0') {
                return Err(SandboxError::InvalidSpec(format!(
                    "invalid key '{key}' in {ctx}"
                )));
            }
            let value = if v.is_null() {
                String::new()
            } else {
                yaml_scalar_to_string(v).ok_or_else(|| {
                    SandboxError::InvalidSpec(format!(
                        "value for '{key}' in {ctx} must be a scalar"
                    ))
                })?
            };
            out.insert(key, value);
        }
        return Ok(out);
    }
    if let Some(arr) = val.as_vec() {
        for item in arr {
            let raw = yaml_scalar_to_string(item).ok_or_else(|| {
                SandboxError::InvalidSpec(format!("list entries in {ctx} must be strings"))
            })?;
            let (k, v) = raw.split_once('=').unwrap_or((raw.as_str(), ""));
            if k.is_empty() || k.contains('\0') {
                return Err(SandboxError::InvalidSpec(format!(
                    "invalid key '{k}' in {ctx}"
                )));
            }
            out.insert(k.to_owned(), v.to_owned());
        }
        return Ok(out);
    }
    Err(SandboxError::InvalidSpec(format!(
        "{ctx} must be a mapping or list"
    )))
}

fn parse_restart_policy(
    svc_hash: &yaml_rust2::yaml::Hash,
    svc_name: &str,
) -> Result<Option<RestartSpec>, SandboxError> {
    let Some(raw) = map_get_str(svc_hash, "restart")? else {
        return Ok(None);
    };
    parse_restart_policy_str(&raw, svc_name).map(Some)
}

pub(crate) fn parse_restart_policy_str(
    raw: &str,
    svc_name: &str,
) -> Result<RestartSpec, SandboxError> {
    let trimmed = raw.trim();
    if let Some(retries_str) = trimmed.strip_prefix("on-failure:") {
        let retries = retries_str.parse::<u32>().map_err(|_| {
            SandboxError::InvalidSpec(format!(
                "invalid restart policy '{trimmed}' in service '{svc_name}'"
            ))
        })?;
        return Ok(RestartSpec {
            name: "on-failure".to_owned(),
            maximum_retry_count: retries,
        });
    }
    match trimmed {
        "no" | "always" | "unless-stopped" | "on-failure" => Ok(RestartSpec {
            name: trimmed.to_owned(),
            maximum_retry_count: 0,
        }),
        other => Err(SandboxError::InvalidSpec(format!(
            "unsupported restart policy '{other}' in service '{svc_name}'"
        ))),
    }
}

fn parse_service_ports(
    svc_hash: &yaml_rust2::yaml::Hash,
    svc_name: &str,
) -> Result<Vec<ComposePort>, SandboxError> {
    let Some(ports_val) = map_get(svc_hash, "ports") else {
        return Ok(Vec::new());
    };
    if ports_val.is_null() {
        return Ok(Vec::new());
    }
    let arr = ports_val.as_vec().ok_or_else(|| {
        SandboxError::InvalidSpec(format!("service '{svc_name}' ports must be a list"))
    })?;
    let mut ports = Vec::with_capacity(arr.len());
    for item in arr {
        if let Some(raw) = yaml_scalar_to_string(item) {
            ports.push(parse_short_port(&raw, svc_name)?);
        } else if let Some(h) = item.as_hash() {
            let proto = map_get_str(h, "protocol")?.unwrap_or_else(|| "tcp".to_owned());
            if !proto.eq_ignore_ascii_case("tcp") {
                return Err(SandboxError::PolicyViolation(format!(
                    "service '{svc_name}' publishes non-TCP port protocol '{proto}', which is unsupported"
                )));
            }
            if let Some(hip) = map_get_str(h, "host_ip")? {
                validate_compose_host_ip(&hip, svc_name)?;
            }
            let target_str = map_get_str(h, "target")?.ok_or_else(|| {
                SandboxError::InvalidSpec(format!(
                    "service '{svc_name}' long port entry requires 'target'"
                ))
            })?;
            let container_port = parse_nonzero_port(&target_str, svc_name)?;
            let host_port = match map_get_str(h, "published")? {
                Some(p) if !p.is_empty() && p != "0" => Some(parse_nonzero_port(&p, svc_name)?),
                _ => None,
            };
            ports.push(ComposePort {
                host_port,
                container_port,
            });
        } else {
            return Err(SandboxError::InvalidSpec(format!(
                "invalid port entry in service '{svc_name}'"
            )));
        }
    }
    Ok(ports)
}

pub(crate) fn parse_short_port(raw: &str, svc_name: &str) -> Result<ComposePort, SandboxError> {
    let trimmed = raw.trim();
    let (port_part, proto) = match trimmed.rsplit_once('/') {
        Some((p, pr)) => (p, pr),
        None => (trimmed, "tcp"),
    };
    if !proto.eq_ignore_ascii_case("tcp") {
        return Err(SandboxError::PolicyViolation(format!(
            "service '{svc_name}' port '{raw}' uses non-TCP protocol '{proto}'"
        )));
    }

    let segments: Vec<&str> = port_part.split(':').collect();
    match segments.as_slice() {
        [ctr] => Ok(ComposePort {
            host_port: None,
            container_port: parse_nonzero_port(ctr, svc_name)?,
        }),
        [host, ctr] => {
            let hp = if host.is_empty() || *host == "0" {
                None
            } else {
                Some(parse_nonzero_port(host, svc_name)?)
            };
            Ok(ComposePort {
                host_port: hp,
                container_port: parse_nonzero_port(ctr, svc_name)?,
            })
        }
        [ip, host, ctr] => {
            validate_compose_host_ip(ip, svc_name)?;
            let hp = if host.is_empty() || *host == "0" {
                None
            } else {
                Some(parse_nonzero_port(host, svc_name)?)
            };
            Ok(ComposePort {
                host_port: hp,
                container_port: parse_nonzero_port(ctr, svc_name)?,
            })
        }
        _ => Err(SandboxError::InvalidSpec(format!(
            "invalid port mapping '{raw}' in service '{svc_name}'"
        ))),
    }
}

fn validate_compose_host_ip(ip: &str, svc_name: &str) -> Result<(), SandboxError> {
    let trimmed = ip.trim();
    if trimmed.is_empty() || trimmed == "127.0.0.1" || trimmed == "0.0.0.0" {
        return Ok(());
    }
    Err(SandboxError::PolicyViolation(format!(
        "service '{svc_name}' binds non-loopback host_ip '{ip}'; mini-pod forwards published ports strictly on 127.0.0.1"
    )))
}

fn parse_nonzero_port(raw: &str, svc_name: &str) -> Result<u16, SandboxError> {
    let port = raw.trim().parse::<u16>().map_err(|_| {
        SandboxError::InvalidSpec(format!(
            "invalid TCP port '{raw}' in service '{svc_name}'"
        ))
    })?;
    if port == 0 {
        return Err(SandboxError::InvalidSpec(format!(
            "container TCP port cannot be 0 in service '{svc_name}'"
        )));
    }
    Ok(port)
}

fn parse_service_expose(
    svc_hash: &yaml_rust2::yaml::Hash,
    svc_name: &str,
) -> Result<Vec<u16>, SandboxError> {
    let Some(exp_val) = map_get(svc_hash, "expose") else {
        return Ok(Vec::new());
    };
    if exp_val.is_null() {
        return Ok(Vec::new());
    }
    let arr = exp_val.as_vec().ok_or_else(|| {
        SandboxError::InvalidSpec(format!("service '{svc_name}' expose must be a list"))
    })?;
    let mut out = Vec::with_capacity(arr.len());
    for item in arr {
        let s = yaml_scalar_to_string(item).ok_or_else(|| {
            SandboxError::InvalidSpec(format!(
                "service '{svc_name}' expose entries must be scalars"
            ))
        })?;
        let base = s.split('/').next().unwrap_or(&s);
        out.push(parse_nonzero_port(base, svc_name)?);
    }
    Ok(out)
}

fn parse_service_mounts(
    svc_hash: &yaml_rust2::yaml::Hash,
    svc_name: &str,
    project_name: &str,
    declared_volumes: &mut BTreeMap<String, VolumeDecl>,
) -> Result<Vec<ComposeMount>, SandboxError> {
    let mut mounts = Vec::new();

    if let Some(vols_val) = map_get(svc_hash, "volumes") {
        if !vols_val.is_null() {
            let arr = vols_val.as_vec().ok_or_else(|| {
                SandboxError::InvalidSpec(format!("service '{svc_name}' volumes must be a list"))
            })?;

            for item in arr {
                if let Some(raw) = item.as_str() {
                    mounts.push(parse_short_volume_mount(
                        raw,
                        svc_name,
                        project_name,
                        declared_volumes,
                    )?);
                } else if let Some(vh) = item.as_hash() {
                    let kind = map_get_str(vh, "type")?.unwrap_or_else(|| "volume".to_owned());
                    let target = map_get_str(vh, "target")?.ok_or_else(|| {
                        SandboxError::InvalidSpec(format!(
                            "service '{svc_name}' volume object requires 'target'"
                        ))
                    })?;
                    let read_only = map_get(vh, "read_only")
                        .and_then(Yaml::as_bool)
                        .unwrap_or(false);
                    match kind.as_str() {
                        "tmpfs" => mounts.push(ComposeMount::Tmpfs { target }),
                        "volume" => {
                            let src_key = map_get_str(vh, "source")?.ok_or_else(|| {
                                SandboxError::InvalidSpec(format!(
                                    "service '{svc_name}' named volume mount requires 'source'"
                                ))
                            })?;
                            let actual_src = resolve_named_volume(
                                &src_key,
                                svc_name,
                                project_name,
                                declared_volumes,
                            )?;
                            mounts.push(ComposeMount::Volume {
                                volume_key: Some(src_key),
                                source_volume: actual_src,
                                target,
                                read_only,
                            });
                        }
                        "bind" => {
                            return Err(SandboxError::PolicyViolation(format!(
                                "service '{svc_name}' requests a host bind mount to '{target}', which mini-pod forbids to preserve VM isolation; use a named volume or 'build:' instead"
                            )));
                        }
                        other => {
                            return Err(SandboxError::InvalidSpec(format!(
                                "unsupported mount type '{other}' in service '{svc_name}'"
                            )));
                        }
                    }
                } else {
                    return Err(SandboxError::InvalidSpec(format!(
                        "invalid volume entry in service '{svc_name}'"
                    )));
                }
            }
        }
    }

    if let Some(tmpfs_val) = map_get(svc_hash, "tmpfs") {
        if let Some(s) = tmpfs_val.as_str() {
            mounts.push(ComposeMount::Tmpfs {
                target: s.to_owned(),
            });
        } else if let Some(arr) = tmpfs_val.as_vec() {
            for item in arr {
                let s = yaml_scalar_to_string(item).ok_or_else(|| {
                    SandboxError::InvalidSpec(format!(
                        "service '{svc_name}' tmpfs entries must be strings"
                    ))
                })?;
                mounts.push(ComposeMount::Tmpfs { target: s });
            }
        }
    }

    Ok(mounts)
}

fn parse_short_volume_mount(
    raw: &str,
    svc_name: &str,
    project_name: &str,
    declared_volumes: &mut BTreeMap<String, VolumeDecl>,
) -> Result<ComposeMount, SandboxError> {
    let trimmed = raw.trim();
    // Detect Windows drive-letter host bind (`C:\foo:/bar`) or relative/absolute host path (`./foo:/bar`, `/foo:/bar`).
    if looks_like_host_bind(trimmed) {
        return Err(SandboxError::PolicyViolation(format!(
            "service '{svc_name}' uses host bind mount '{trimmed}', which mini-pod forbids to preserve VM isolation; use a named volume (e.g. 'app_data:/data') or 'build:' instead"
        )));
    }

    let parts: Vec<&str> = trimmed.split(':').collect();
    match parts.as_slice() {
        [src, dst] => {
            let actual = resolve_named_volume(src, svc_name, project_name, declared_volumes)?;
            Ok(ComposeMount::Volume {
                volume_key: Some((*src).to_owned()),
                source_volume: actual,
                target: (*dst).to_owned(),
                read_only: false,
            })
        }
        [src, dst, mode] => {
            let read_only = match *mode {
                "ro" => true,
                "rw" => false,
                other => {
                    return Err(SandboxError::InvalidSpec(format!(
                        "unsupported volume mode '{other}' in '{trimmed}' (expected 'ro' or 'rw')"
                    )));
                }
            };
            let actual = resolve_named_volume(src, svc_name, project_name, declared_volumes)?;
            Ok(ComposeMount::Volume {
                volume_key: Some((*src).to_owned()),
                source_volume: actual,
                target: (*dst).to_owned(),
                read_only,
            })
        }
        _ => Err(SandboxError::InvalidSpec(format!(
            "invalid volume specification '{trimmed}' in service '{svc_name}'"
        ))),
    }
}

fn looks_like_host_bind(raw: &str) -> bool {
    if raw.starts_with('.') || raw.starts_with('/') || raw.starts_with('~') || raw.starts_with('\\')
    {
        return true;
    }
    let bytes = raw.as_bytes();
    if bytes.len() >= 3 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' && (bytes[2] == b'\\' || bytes[2] == b'/') {
        return true;
    }
    if let Some((src, _)) = raw.split_once(':') {
        if src.contains('/') || src.contains('\\') {
            return true;
        }
    }
    false
}

fn resolve_named_volume(
    vol_key: &str,
    svc_name: &str,
    project_name: &str,
    declared_volumes: &mut BTreeMap<String, VolumeDecl>,
) -> Result<String, SandboxError> {
    validate_safe_identifier(vol_key, &format!("service '{svc_name}' volume name"))?;
    if let Some(decl) = declared_volumes.get(vol_key) {
        return Ok(decl.actual_name.clone());
    }
    // Auto-register undeclared named volumes under project scope for convenience.
    let actual_name = format!("{project_name}_{vol_key}");
    declared_volumes.insert(
        vol_key.to_owned(),
        VolumeDecl {
            actual_name: actual_name.clone(),
            external: false,
        },
    );
    Ok(actual_name)
}

fn parse_service_networks(
    svc_hash: &yaml_rust2::yaml::Hash,
    svc_name: &str,
    declared_networks: &BTreeMap<String, String>,
) -> Result<Vec<ServiceNetwork>, SandboxError> {
    let Some(nets_val) = map_get(svc_hash, "networks") else {
        return Ok(vec![ServiceNetwork {
            network_key: "default".to_owned(),
            aliases: vec![svc_name.to_owned()],
        }]);
    };
    if nets_val.is_null() {
        return Ok(vec![ServiceNetwork {
            network_key: "default".to_owned(),
            aliases: vec![svc_name.to_owned()],
        }]);
    }

    let mut result = Vec::new();
    if let Some(arr) = nets_val.as_vec() {
        for item in arr {
            let key = yaml_scalar_to_string(item).ok_or_else(|| {
                SandboxError::InvalidSpec(format!(
                    "service '{svc_name}' networks list entries must be strings"
                ))
            })?;
            if key != "default" && !declared_networks.contains_key(&key) {
                return Err(SandboxError::InvalidSpec(format!(
                    "service '{svc_name}' references undeclared network '{key}'"
                )));
            }
            result.push(ServiceNetwork {
                network_key: key,
                aliases: vec![svc_name.to_owned()],
            });
        }
    } else if let Some(hash) = nets_val.as_hash() {
        for (k, v) in hash {
            let key = yaml_key_str(k, &format!("services.{svc_name}.networks"))?;
            if key != "default" && !declared_networks.contains_key(&key) {
                return Err(SandboxError::InvalidSpec(format!(
                    "service '{svc_name}' references undeclared network '{key}'"
                )));
            }
            let mut aliases = vec![svc_name.to_owned()];
            if let Some(nh) = v.as_hash() {
                if let Some(al_val) = map_get(nh, "aliases") {
                    if let Some(al_arr) = al_val.as_vec() {
                        for item in al_arr {
                            if let Some(a) = yaml_scalar_to_string(item) {
                                if !aliases.contains(&a) {
                                    aliases.push(a);
                                }
                            }
                        }
                    }
                }
            }
            result.push(ServiceNetwork {
                network_key: key,
                aliases,
            });
        }
    } else {
        return Err(SandboxError::InvalidSpec(format!(
            "service '{svc_name}' networks must be a list or mapping"
        )));
    }

    if result.is_empty() {
        result.push(ServiceNetwork {
            network_key: "default".to_owned(),
            aliases: vec![svc_name.to_owned()],
        });
    }
    Ok(result)
}

fn parse_depends_on(
    svc_hash: &yaml_rust2::yaml::Hash,
    svc_name: &str,
) -> Result<Vec<String>, SandboxError> {
    let Some(dep_val) = map_get(svc_hash, "depends_on") else {
        return Ok(Vec::new());
    };
    if dep_val.is_null() {
        return Ok(Vec::new());
    }
    let mut deps = Vec::new();
    if let Some(arr) = dep_val.as_vec() {
        for item in arr {
            let d = yaml_scalar_to_string(item).ok_or_else(|| {
                SandboxError::InvalidSpec(format!(
                    "service '{svc_name}' depends_on list entries must be strings"
                ))
            })?;
            if !deps.contains(&d) {
                deps.push(d);
            }
        }
        return Ok(deps);
    }
    if let Some(hash) = dep_val.as_hash() {
        for (k, _) in hash {
            let d = yaml_key_str(k, &format!("services.{svc_name}.depends_on"))?;
            if !deps.contains(&d) {
                deps.push(d);
            }
        }
        return Ok(deps);
    }
    Err(SandboxError::InvalidSpec(format!(
        "service '{svc_name}' depends_on must be a list or mapping"
    )))
}

fn topological_sort_services(
    services: &BTreeMap<String, ServiceSpec>,
) -> Result<Vec<String>, SandboxError> {
    let mut in_degree: BTreeMap<String, usize> = BTreeMap::new();
    let mut dependents: BTreeMap<String, Vec<String>> = BTreeMap::new();

    for name in services.keys() {
        in_degree.insert(name.clone(), 0);
        dependents.insert(name.clone(), Vec::new());
    }

    for (svc_name, svc) in services {
        for dep in &svc.depends_on {
            if dep == svc_name {
                return Err(SandboxError::InvalidSpec(format!(
                    "service '{svc_name}' cannot depend on itself"
                )));
            }
            if !services.contains_key(dep) {
                return Err(SandboxError::InvalidSpec(format!(
                    "service '{svc_name}' depends_on unknown service '{dep}'"
                )));
            }
            *in_degree.get_mut(svc_name).unwrap() += 1;
            dependents.get_mut(dep).unwrap().push(svc_name.clone());
        }
    }

    let mut ready: VecDeque<String> = in_degree
        .iter()
        .filter(|&(_, &deg)| deg == 0)
        .map(|(k, _)| k.clone())
        .collect();
    let mut order = Vec::with_capacity(services.len());

    while let Some(node) = ready.pop_front() {
        order.push(node.clone());
        if let Some(children) = dependents.get(&node) {
            for child in children {
                let deg = in_degree.get_mut(child).unwrap();
                *deg -= 1;
                if *deg == 0 {
                    ready.push_back(child.clone());
                }
            }
        }
    }

    if order.len() != services.len() {
        return Err(SandboxError::InvalidSpec(
            "circular depends_on cycle detected in Compose services".to_owned(),
        ));
    }
    Ok(order)
}

fn build_container_create_payload(spec: &ComposeSpec, svc: &ServiceSpec) -> Value {
    let mut root = Map::new();
    root.insert("Image".to_owned(), Value::String(svc.image.clone()));

    if let Some(ref cmd) = svc.command {
        root.insert("Cmd".to_owned(), json!(cmd));
    }
    if let Some(ref ep) = svc.entrypoint {
        root.insert("Entrypoint".to_owned(), json!(ep));
    }
    if !svc.env.is_empty() {
        let env_vec: Vec<String> = svc.env.iter().map(|(k, v)| format!("{k}={v}")).collect();
        root.insert("Env".to_owned(), json!(env_vec));
    }
    if let Some(ref wd) = svc.working_dir {
        root.insert("WorkingDir".to_owned(), Value::String(wd.clone()));
    }
    if let Some(ref u) = svc.user {
        root.insert("User".to_owned(), Value::String(u.clone()));
    }
    if let Some(ref hn) = svc.hostname {
        root.insert("Hostname".to_owned(), Value::String(hn.clone()));
    }

    root.insert(
        "Labels".to_owned(),
        json!({
            LABEL_PROJECT: spec.project_name,
            LABEL_SERVICE: svc.name,
        }),
    );

    let mut hc = Map::new();
    insert_port_bindings_json(&mut root, &mut hc, &svc.ports, &svc.expose);

    if !svc.mounts.is_empty() {
        let mounts_json: Vec<Value> = svc
            .mounts
            .iter()
            .map(|m| match m {
                ComposeMount::Volume {
                    source_volume,
                    target,
                    read_only,
                    ..
                } => json!({
                    "Type": "volume",
                    "Source": source_volume,
                    "Target": target,
                    "ReadOnly": read_only,
                }),
                ComposeMount::Tmpfs { target } => json!({
                    "Type": "tmpfs",
                    "Target": target,
                }),
            })
            .collect();
        hc.insert("Mounts".to_owned(), Value::Array(mounts_json));
    }

    if let Some(ref restart) = svc.restart {
        hc.insert(
            "RestartPolicy".to_owned(),
            json!({
                "Name": restart.name,
                "MaximumRetryCount": restart.maximum_retry_count,
            }),
        );
    }

    if matches!(svc.network_mode.as_deref(), Some("none")) {
        hc.insert("NetworkMode".to_owned(), Value::String("none".to_owned()));
    } else if let Some(primary_net) = svc.networks.first() {
        let actual_net = spec
            .networks
            .get(&primary_net.network_key)
            .cloned()
            .unwrap_or_else(|| format!("{}_{}", spec.project_name, primary_net.network_key));
        hc.insert("NetworkMode".to_owned(), Value::String(actual_net.clone()));
        root.insert(
            "NetworkingConfig".to_owned(),
            json!({
                "EndpointsConfig": {
                    actual_net: {
                        "Aliases": primary_net.aliases,
                    }
                }
            }),
        );
    }

    root.insert("HostConfig".to_owned(), Value::Object(hc));
    Value::Object(root)
}

pub(crate) fn insert_port_bindings_json(
    root: &mut Map<String, Value>,
    hc: &mut Map<String, Value>,
    ports: &[ComposePort],
    expose: &[u16],
) {
    let mut exposed_ports = Map::new();
    for &p in expose {
        exposed_ports.insert(format!("{p}/tcp"), json!({}));
    }
    let mut port_bindings: BTreeMap<String, Vec<Value>> = BTreeMap::new();
    for port in ports {
        let key = format!("{}/tcp", port.container_port);
        exposed_ports.insert(key.clone(), json!({}));
        let host_port_str = port.host_port.map(|hp| hp.to_string()).unwrap_or_default();
        port_bindings.entry(key).or_default().push(json!({
            "HostIp": "127.0.0.1",
            "HostPort": host_port_str,
        }));
    }
    if !exposed_ports.is_empty() {
        root.insert("ExposedPorts".to_owned(), Value::Object(exposed_ports));
    }
    if !port_bindings.is_empty() {
        let pb_map: Map<String, Value> = port_bindings
            .into_iter()
            .map(|(k, v)| (k, Value::Array(v)))
            .collect();
        hc.insert("PortBindings".to_owned(), Value::Object(pb_map));
    }
}

async fn guest_image_exists(
    client: &SandboxClient,
    sandbox_id: &SandboxId,
    image: &str,
) -> Result<bool, SandboxError> {
    let req = ExecRequest {
        target: ExecTarget::Guest,
        argv: vec![
            "/usr/bin/podman".to_owned(),
            "image".to_owned(),
            "exists".to_owned(),
            "--".to_owned(),
            image.to_owned(),
        ],
        env: BTreeMap::new(),
        cwd: None,
        user: None,
        deadline: Duration::from_secs(20),
        stdout_budget_bytes: 16 * 1024,
        stderr_budget_bytes: 64 * 1024,
    };
    let out = client.exec_collect(sandbox_id, req).await?;
    Ok(out.exit.code == Some(0))
}

async fn pull_guest_image(
    client: &SandboxClient,
    sandbox_id: &SandboxId,
    image: &str,
    deadline: Duration,
    stream_to_stdio: bool,
) -> Result<(), SandboxError> {
    let req = ExecRequest {
        target: ExecTarget::Guest,
        argv: vec![
            "/bin/sh".to_owned(),
            "-euc".to_owned(),
            "(grep -q ' /var/cache ' /proc/mounts 2>/dev/null || (mkdir -p /var/tmp/var-cache && mount --bind /var/tmp/var-cache /var/cache 2>/dev/null || true)) && exec /usr/bin/podman pull -- \"$1\"".to_owned(),
            "sh".to_owned(),
            image.to_owned(),
        ],
        env: BTreeMap::new(),
        cwd: None,
        user: None,
        deadline,
        stdout_budget_bytes: 2 * 1024 * 1024,
        stderr_budget_bytes: 2 * 1024 * 1024,
    };
    let mut stream = client.exec_stream(sandbox_id, req).await?;
    stream.close_stdin();

    if !stream_to_stdio {
        let collected = stream.collect().await?;
        if collected.exit.code != Some(0) {
            return Err(SandboxError::Transport(format!(
                "failed pulling image '{image}': {}",
                String::from_utf8_lossy(&collected.stderr).trim()
            )));
        }
        return Ok(());
    }

    let mut stderr_io = tokio::io::stderr();
    let mut err_buf = Vec::new();
    while let Some(chunk) = stream.next_output().await {
        err_buf.extend_from_slice(&chunk.data);
        let _ = stderr_io.write_all(&chunk.data).await;
        let _ = stderr_io.flush().await;
    }
    let exit = stream.wait_exit().await?;
    if exit.code != Some(0) || exit.timed_out {
        return Err(SandboxError::Transport(format!(
            "failed pulling image '{image}' (exit={:?}, timed_out={}): {}",
            exit.code,
            exit.timed_out,
            String::from_utf8_lossy(&err_buf).trim()
        )));
    }
    Ok(())
}

async fn ensure_network(
    docker_ep: &ControlEndpoint,
    project: &str,
    net_key: &str,
    actual_name: &str,
) -> Result<(), SandboxError> {
    let get_path = format!("/networks/{}", percent_encode_component(actual_name));
    let (st, _) = docker_json_request(docker_ep, "GET", &get_path, None).await?;
    if st == 200 {
        return Ok(());
    }
    let payload = json!({
        "Name": actual_name,
        "Driver": "bridge",
        "Labels": {
            LABEL_PROJECT: project,
            LABEL_NETWORK: net_key,
        }
    });
    let (cst, cbody) =
        docker_json_request(docker_ep, "POST", "/networks/create", Some(&payload)).await?;
    if (200..300).contains(&cst) || cst == 409 {
        return Ok(());
    }
    Err(docker_http_error(
        &format!("create network '{actual_name}'"),
        cst,
        &cbody,
    ))
}

async fn ensure_volume(
    docker_ep: &ControlEndpoint,
    project: &str,
    vol_key: &str,
    actual_name: &str,
) -> Result<(), SandboxError> {
    let get_path = format!("/volumes/{}", percent_encode_component(actual_name));
    let (st, _) = docker_json_request(docker_ep, "GET", &get_path, None).await?;
    if st == 200 {
        return Ok(());
    }
    let payload = json!({
        "Name": actual_name,
        "Labels": {
            LABEL_PROJECT: project,
            LABEL_VOLUME: vol_key,
        }
    });
    let (cst, cbody) =
        docker_json_request(docker_ep, "POST", "/volumes/create", Some(&payload)).await?;
    if (200..300).contains(&cst) {
        return Ok(());
    }
    Err(docker_http_error(
        &format!("create volume '{actual_name}'"),
        cst,
        &cbody,
    ))
}

async fn remove_container_if_exists(
    docker_ep: &ControlEndpoint,
    container_name: &str,
) -> Result<(), SandboxError> {
    let enc = percent_encode_component(container_name);
    let (st, _) = docker_json_request(docker_ep, "GET", &format!("/containers/{enc}/json"), None).await?;
    if st == 404 {
        return Ok(());
    }
    let _ = docker_json_request(docker_ep, "POST", &format!("/containers/{enc}/stop?t=2"), None).await?;
    let (dst, dbody) =
        docker_json_request(docker_ep, "DELETE", &format!("/containers/{enc}?force=true"), None)
            .await?;
    if (200..300).contains(&dst) || dst == 404 {
        return Ok(());
    }
    Err(docker_http_error(
        &format!("remove previous container '{container_name}'"),
        dst,
        &dbody,
    ))
}

async fn list_project_containers(
    docker_ep: &ControlEndpoint,
    project_name: &str,
) -> Result<Vec<Value>, SandboxError> {
    let (st, body) =
        docker_json_request(docker_ep, "GET", "/containers/json?all=true", None).await?;
    if st != 200 {
        return Err(docker_http_error("list containers", st, &body));
    }
    let arr: Vec<Value> = serde_json::from_slice(&body)
        .map_err(|err| SandboxError::Transport(format!("invalid /containers/json body: {err}")))?;

    let mut out = Vec::new();
    for item in arr {
        if item["Labels"][LABEL_PROJECT].as_str() != Some(project_name) {
            continue;
        }
        let id = item["Id"].as_str().unwrap_or("").to_owned();
        let service = item["Labels"][LABEL_SERVICE]
            .as_str()
            .unwrap_or("-")
            .to_owned();
        let name = item["Names"]
            .as_array()
            .and_then(|a| a.first())
            .and_then(Value::as_str)
            .map(|n| n.trim_start_matches('/').to_owned())
            .unwrap_or_else(|| id.chars().take(12).collect());
        let image = item["Image"].as_str().unwrap_or("-").to_owned();
        let state = item["State"].as_str().unwrap_or("-").to_owned();
        let status = item["Status"].as_str().unwrap_or("").to_owned();
        let ports = format_container_list_ports(&item["Ports"]);

        out.push(json!({
            "id": id,
            "service": service,
            "name": name,
            "image": image,
            "state": state,
            "status": status,
            "ports": ports,
        }));
    }
    Ok(out)
}

pub(crate) fn extract_inspected_host_ports(inspect: &Value) -> Vec<String> {
    let mut ports = Vec::new();
    let Some(map) = inspect["NetworkSettings"]["Ports"].as_object() else {
        return ports;
    };
    for (ctr_key, bindings_val) in map {
        if let Some(arr) = bindings_val.as_array() {
            for b in arr {
                let ip = b["HostIp"].as_str().unwrap_or("127.0.0.1");
                let hp = b["HostPort"].as_str().unwrap_or("");
                if !hp.is_empty() {
                    ports.push(format!("{ip}:{hp}->{ctr_key}"));
                }
            }
        }
    }
    ports
}

pub(crate) fn format_container_list_ports(ports_val: &Value) -> String {
    let Some(arr) = ports_val.as_array() else {
        return "-".to_owned();
    };
    let mut labels = Vec::new();
    for entry in arr {
        let priv_port = entry["PrivatePort"].as_u64().unwrap_or(0);
        let typ = entry["Type"].as_str().unwrap_or("tcp");
        if let Some(pub_port) = entry["PublicPort"].as_u64() {
            let ip = entry["IP"].as_str().unwrap_or("127.0.0.1");
            labels.push(format!("{ip}:{pub_port}->{priv_port}/{typ}"));
        } else if priv_port > 0 {
            labels.push(format!("{priv_port}/{typ}"));
        }
    }
    if labels.is_empty() {
        "-".to_owned()
    } else {
        labels.join(", ")
    }
}

pub(crate) fn percent_encode_component(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for b in raw.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(char::from(b));
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

pub(crate) fn docker_http_error(op: &str, status: u16, body: &[u8]) -> SandboxError {
    let detail = serde_json::from_slice::<Value>(body)
        .ok()
        .and_then(|v| v["message"].as_str().map(str::to_owned))
        .unwrap_or_else(|| String::from_utf8_lossy(body).trim().to_owned());
    if status == 400 || status == 403 {
        SandboxError::PolicyViolation(format!("Docker API {op} rejected (HTTP {status}): {detail}"))
    } else {
        SandboxError::Transport(format!("Docker API {op} failed (HTTP {status}): {detail}"))
    }
}

/// Sends a single HTTP/1.1 JSON request (`Connection: close`) over the owner-only `DockerCompat` IPC endpoint.
pub(crate) async fn docker_json_request(
    endpoint: &ControlEndpoint,
    method: &str,
    path_and_query: &str,
    json_body: Option<&Value>,
) -> Result<(u16, Vec<u8>), SandboxError> {
    let stream = SandboxClient::new(endpoint.clone())
        .connect_with_connector()
        .await?;
    docker_json_request_over_stream(stream, method, path_and_query, json_body).await
}

async fn docker_json_request_over_stream<S>(
    mut stream: S,
    method: &str,
    path_and_query: &str,
    json_body: Option<&Value>,
) -> Result<(u16, Vec<u8>), SandboxError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let body_bytes = match json_body {
        Some(val) => serde_json::to_vec(val)
            .map_err(|err| SandboxError::Internal(format!("JSON serialize failed: {err}")))?,
        None => Vec::new(),
    };

    let mut head = format!(
        "{method} {path_and_query} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n"
    );
    if json_body.is_some() {
        head.push_str("Content-Type: application/json\r\n");
        head.push_str(&format!("Content-Length: {}\r\n", body_bytes.len()));
    } else if matches!(method, "POST" | "PUT") {
        head.push_str("Content-Length: 0\r\n");
    }
    head.push_str("\r\n");

    stream
        .write_all(head.as_bytes())
        .await
        .map_err(|err| SandboxError::Transport(format!("Docker IPC write failed: {err}")))?;
    if !body_bytes.is_empty() {
        stream
            .write_all(&body_bytes)
            .await
            .map_err(|err| SandboxError::Transport(format!("Docker IPC body write failed: {err}")))?;
    }
    stream
        .flush()
        .await
        .map_err(|err| SandboxError::Transport(format!("Docker IPC flush failed: {err}")))?;

    let mut reader = BufReader::new(stream);
    let status_line = read_http_line_bounded(&mut reader, MAX_HTTP_LINE_BYTES, "status line")
        .await?
        .ok_or_else(|| {
            SandboxError::Transport("unexpected EOF reading Docker IPC response".to_owned())
        })?;

    let mut status_parts = status_line.trim_end().splitn(3, ' ');
    let _http_ver = status_parts.next();
    let status: u16 = status_parts
        .next()
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or_else(|| {
            SandboxError::Transport(format!("malformed Docker HTTP status line '{status_line}'"))
        })?;

    let mut headers: HashMap<String, String> = HashMap::new();
    let mut header_bytes = status_line.len();
    loop {
        let line = read_http_line_bounded(&mut reader, MAX_HTTP_LINE_BYTES, "header line")
            .await?
            .ok_or_else(|| {
                SandboxError::Transport("unexpected EOF in Docker HTTP headers".to_owned())
            })?;
        header_bytes = header_bytes.saturating_add(line.len());
        if header_bytes > MAX_HTTP_HEADER_BYTES {
            return Err(SandboxError::Transport(
                "Docker HTTP response headers exceeded 64 KiB".to_owned(),
            ));
        }
        let trimmed = line.trim_end_matches(['\r', '\n']);
        if trimmed.is_empty() {
            break;
        }
        if let Some((k, v)) = trimmed.split_once(':') {
            headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_owned());
        }
    }

    if (100..200).contains(&status) || status == 204 || status == 304 || method == "HEAD" {
        return Ok((status, Vec::new()));
    }

    let is_chunked = headers
        .get("transfer-encoding")
        .is_some_and(|v| v.to_ascii_lowercase().contains("chunked"));

    if is_chunked {
        let mut out = Vec::new();
        loop {
            let size_line =
                read_http_line_bounded(&mut reader, MAX_HTTP_LINE_BYTES, "chunk size line")
                    .await?
                    .ok_or_else(|| {
                        SandboxError::Transport(
                            "unexpected EOF reading HTTP chunk size".to_owned(),
                        )
                    })?;
            let hex_part = size_line
                .trim()
                .split(';')
                .next()
                .unwrap_or("")
                .trim();
            if hex_part.is_empty()
                || hex_part.len() > 16
                || !hex_part.bytes().all(|b| b.is_ascii_hexdigit())
            {
                return Err(SandboxError::Transport(format!(
                    "invalid HTTP chunk length '{hex_part}'"
                )));
            }
            let chunk_len = usize::from_str_radix(hex_part, 16).map_err(|_| {
                SandboxError::Transport(format!("invalid HTTP chunk length '{hex_part}'"))
            })?;
            if chunk_len == 0 {
                let mut trailer_lines = 0usize;
                let mut trailer_bytes = 0usize;
                loop {
                    let Some(trailer) =
                        read_http_line_bounded(&mut reader, MAX_HTTP_LINE_BYTES, "chunk trailer")
                            .await?
                    else {
                        break;
                    };
                    if trailer.trim_end_matches(['\r', '\n']).is_empty() {
                        break;
                    }
                    trailer_lines += 1;
                    trailer_bytes = trailer_bytes.saturating_add(trailer.len());
                    if trailer_lines > MAX_HTTP_TRAILER_LINES
                        || trailer_bytes > MAX_HTTP_HEADER_BYTES
                    {
                        return Err(SandboxError::Transport(
                            "Docker HTTP chunked trailers exceeded limits".to_owned(),
                        ));
                    }
                }
                break;
            }
            if out.len().saturating_add(chunk_len) > MAX_HTTP_BODY_BYTES {
                return Err(SandboxError::BudgetExceeded(
                    "Docker HTTP chunked response exceeded 16 MiB".to_owned(),
                ));
            }
            let prev_len = out.len();
            out.resize(prev_len + chunk_len, 0);
            reader
                .read_exact(&mut out[prev_len..])
                .await
                .map_err(|err| SandboxError::Transport(format!("chunk data read failed: {err}")))?;
            let mut crlf = [0u8; 2];
            reader
                .read_exact(&mut crlf)
                .await
                .map_err(|err| SandboxError::Transport(format!("chunk CRLF read failed: {err}")))?;
            if crlf != *b"\r\n" {
                return Err(SandboxError::Transport(
                    "missing CRLF after HTTP chunk payload".to_owned(),
                ));
            }
        }
        return Ok((status, out));
    }

    if let Some(cl_raw) = headers.get("content-length") {
        let len = cl_raw.parse::<usize>().map_err(|_| {
            SandboxError::Transport(format!("invalid Content-Length '{cl_raw}'"))
        })?;
        if len > MAX_HTTP_BODY_BYTES {
            return Err(SandboxError::BudgetExceeded(
                "Docker HTTP response exceeded 16 MiB".to_owned(),
            ));
        }
        let mut out = vec![0u8; len];
        reader
            .read_exact(&mut out)
            .await
            .map_err(|err| SandboxError::Transport(format!("Docker HTTP body read failed: {err}")))?;
        return Ok((status, out));
    }

    let mut out = Vec::new();
    let mut limited = reader.take((MAX_HTTP_BODY_BYTES + 1) as u64);
    limited
        .read_to_end(&mut out)
        .await
        .map_err(|err| SandboxError::Transport(format!("Docker HTTP EOF read failed: {err}")))?;
    if out.len() > MAX_HTTP_BODY_BYTES {
        return Err(SandboxError::BudgetExceeded(
            "Docker HTTP response exceeded 16 MiB".to_owned(),
        ));
    }
    Ok((status, out))
}

async fn read_http_line_bounded<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    max_bytes: usize,
    ctx: &str,
) -> Result<Option<String>, SandboxError> {
    let mut buf = Vec::new();
    loop {
        let available = reader.fill_buf().await.map_err(|err| {
            SandboxError::Transport(format!("Docker HTTP {ctx} read failed: {err}"))
        })?;
        if available.is_empty() {
            if buf.is_empty() {
                return Ok(None);
            }
            return String::from_utf8(buf).map(Some).map_err(|err| {
                SandboxError::Transport(format!("Docker HTTP {ctx} is not UTF-8: {err}"))
            });
        }
        if let Some(nl_pos) = available.iter().position(|&b| b == b'\n') {
            let take_len = nl_pos + 1;
            if buf.len().saturating_add(take_len) > max_bytes {
                return Err(SandboxError::Transport(format!(
                    "Docker HTTP {ctx} exceeded {max_bytes} bytes"
                )));
            }
            buf.extend_from_slice(&available[..take_len]);
            reader.consume(take_len);
            return String::from_utf8(buf).map(Some).map_err(|err| {
                SandboxError::Transport(format!("Docker HTTP {ctx} is not UTF-8: {err}"))
            });
        }
        let n = available.len();
        if buf.len().saturating_add(n) > max_bytes {
            return Err(SandboxError::Transport(format!(
                "Docker HTTP {ctx} exceeded {max_bytes} bytes"
            )));
        }
        buf.extend_from_slice(available);
        reader.consume(n);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_compose_yaml_toposorts_depends_on_and_builds_safe_docker_payloads() {
        let yaml = r#"
name: My-Demo_Stack
services:
  web:
    build:
      context: ./frontend
      dockerfile: Dockerfile.web
      args:
        API_URL: http://api:8080
    ports:
      - "8080:80"
      - "0.0.0.0:8443:443/tcp"
    environment:
      - NODE_ENV=production
    depends_on:
      api:
        condition: service_started
    restart: unless-stopped

  api:
    image: echo-http:latest
    command: "/bin/echo-server --port '8080'"
    environment:
      DB_HOST: db
      PORT: 8080
    volumes:
      - app_data:/var/lib/app:rw
    tmpfs:
      - /tmp/run
    depends_on:
      - db

  db:
    image: postgres:16-alpine
    expose:
      - 5432
    volumes:
      - pgdata:/var/lib/postgresql/data

volumes:
  pgdata: {}
"#;
        let spec = parse_compose_yaml(&format!("\u{feff}{yaml}"), Path::new("/proj"), None).unwrap();
        assert_eq!(spec.project_name, "my-demo_stack");
        assert_eq!(spec.startup_order, vec!["db", "api", "web"]);
        assert_eq!(
            spec.networks.get("default").map(String::as_str),
            Some("my-demo_stack_default")
        );
        // Auto-registered `app_data` + declared `pgdata` both scoped to project.
        assert_eq!(
            spec.volumes["pgdata"].actual_name,
            "my-demo_stack_pgdata"
        );
        assert_eq!(
            spec.volumes["app_data"].actual_name,
            "my-demo_stack_app_data"
        );

        let api = &spec.services["api"];
        assert_eq!(
            api.command.as_deref(),
            Some(&["/bin/echo-server".to_owned(), "--port".to_owned(), "8080".to_owned()][..])
        );
        let api_payload = build_container_create_payload(&spec, api);
        assert_eq!(api_payload["HostConfig"]["Mounts"][0]["Type"], "volume");
        assert_eq!(
            api_payload["HostConfig"]["Mounts"][0]["Source"],
            "my-demo_stack_app_data"
        );
        assert_eq!(api_payload["HostConfig"]["Mounts"][1]["Type"], "tmpfs");
        assert_eq!(
            api_payload["HostConfig"]["NetworkMode"],
            "my-demo_stack_default"
        );
        assert_eq!(
            api_payload["NetworkingConfig"]["EndpointsConfig"]["my-demo_stack_default"]["Aliases"][0],
            "api"
        );

        let web = &spec.services["web"];
        assert_eq!(web.image, "my-demo_stack-web:latest");
        let web_payload = build_container_create_payload(&spec, web);
        assert_eq!(
            web_payload["HostConfig"]["PortBindings"]["80/tcp"][0]["HostPort"],
            "8080"
        );
        assert_eq!(
            web_payload["HostConfig"]["PortBindings"]["443/tcp"][0]["HostIp"],
            "127.0.0.1"
        );
    }

    #[test]
    fn rejects_host_bind_mounts_privileged_and_circular_depends_on() {
        let bind_yaml = r#"
services:
  app:
    image: alpine:latest
    volumes:
      - ./host_src:/app
"#;
        assert!(matches!(
            parse_compose_yaml(bind_yaml, Path::new("."), Some("p")),
            Err(SandboxError::PolicyViolation(_))
        ));

        let win_bind_yaml = r#"
services:
  app:
    image: alpine:latest
    volumes:
      - C:\Users\Gem\src:/app
"#;
        assert!(matches!(
            parse_compose_yaml(win_bind_yaml, Path::new("."), Some("p")),
            Err(SandboxError::PolicyViolation(_))
        ));

        let priv_yaml = r#"
services:
  app:
    image: alpine:latest
    privileged: true
"#;
        assert!(matches!(
            parse_compose_yaml(priv_yaml, Path::new("."), Some("p")),
            Err(SandboxError::PolicyViolation(_))
        ));

        let cycle_yaml = r#"
services:
  a:
    image: alpine:latest
    depends_on: [b]
  b:
    image: alpine:latest
    depends_on: [a]
"#;
        assert!(matches!(
            parse_compose_yaml(cycle_yaml, Path::new("."), Some("p")),
            Err(SandboxError::InvalidSpec(_))
        ));
    }

    #[tokio::test]
    async fn confines_build_context_dockerfile_and_env_file_and_bounds_http_lines() {
        let tmp = std::env::temp_dir().join(format!("minipod-compose-confine-{}", std::process::id()));
        let _ = fs::remove_dir_all(&tmp);
        let proj = tmp.join("project");
        let outside = tmp.join("outside");
        fs::create_dir_all(&proj).unwrap();
        fs::create_dir_all(&outside).unwrap();
        fs::write(outside.join("secret.env"), "SECRET=leaked\n").unwrap();
        fs::write(proj.join("app.env"), "APP_MODE=safe\n").unwrap();

        // 1. Valid in-project `env_file` and `build.context` succeed.
        let ok_yaml = r#"
services:
  app:
    build:
      context: ./sub
      dockerfile: Dockerfile
    env_file:
      - ./app.env
"#;
        let ok_spec = parse_compose_yaml(ok_yaml, &proj, Some("demo")).unwrap();
        assert_eq!(
            ok_spec.services["app"].env.get("APP_MODE").map(String::as_str),
            Some("safe")
        );

        // 2. Traversal `..` and external absolute paths in `build.context`, `dockerfile`, and `env_file` fail.
        for bad_yaml in [
            "services:\n  app:\n    build: ../outside\n",
            "services:\n  app:\n    build: /etc\n",
            "services:\n  app:\n    build: C:\\Windows\n",
            "services:\n  app:\n    build:\n      context: .\n      dockerfile: ../Dockerfile\n",
            "services:\n  app:\n    image: alpine:latest\n    env_file: ../outside/secret.env\n",
            "services:\n  app:\n    image: alpine:latest\n    env_file: /etc/passwd\n",
        ] {
            let res = parse_compose_yaml(bad_yaml, &proj, Some("demo"));
            assert!(
                matches!(
                    res,
                    Err(SandboxError::PolicyViolation(_) | SandboxError::InvalidSpec(_))
                ),
                "expected confinement rejection for:\n{bad_yaml}\ngot: {res:?}"
            );
        }

        // 3. Windows junction / Unix symlink inside project escaping to `outside` is rejected.
        #[cfg(windows)]
        {
            let junc = proj.join("linked_out");
            let st = std::process::Command::new("cmd")
                .args([
                    "/C",
                    "mklink",
                    "/J",
                    &junc.to_string_lossy(),
                    &outside.to_string_lossy(),
                ])
                .status()
                .unwrap();
            assert!(st.success());
            let junc_env_yaml =
                "services:\n  app:\n    image: alpine:latest\n    env_file: ./linked_out/secret.env\n";
            assert!(matches!(
                parse_compose_yaml(junc_env_yaml, &proj, Some("demo")),
                Err(SandboxError::PolicyViolation(_))
            ));
            let junc_ctx_yaml = "services:\n  app:\n    build: ./linked_out\n";
            assert!(matches!(
                parse_compose_yaml(junc_ctx_yaml, &proj, Some("demo")),
                Err(SandboxError::PolicyViolation(_))
            ));
        }
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(&outside, proj.join("linked_out")).unwrap();
            let sym_env_yaml =
                "services:\n  app:\n    image: alpine:latest\n    env_file: ./linked_out/secret.env\n";
            assert!(matches!(
                parse_compose_yaml(sym_env_yaml, &proj, Some("demo")),
                Err(SandboxError::PolicyViolation(_))
            ));
        }

        // 4. `docker_json_request_over_stream` bounds oversized HTTP lines before `\n`.
        let (client_io, mut server_io) = tokio::io::duplex(32 * 1024);
        tokio::spawn(async move {
            let mut req_drain = [0u8; 512];
            let _ = server_io.read(&mut req_drain).await;
            let huge_header = vec![b'X'; MAX_HTTP_LINE_BYTES + 512];
            let _ = server_io.write_all(b"HTTP/1.1 200 OK\r\nX-Long: ").await;
            let _ = server_io.write_all(&huge_header).await;
            let _ = server_io.shutdown().await;
        });
        let err = docker_json_request_over_stream(client_io, "GET", "/_ping", None)
            .await
            .unwrap_err();
        assert!(matches!(err, SandboxError::Transport(_)), "got {err:?}");

        // 5. network_mode: none, unsupported network_mode, duplicate container_name, and env_file quoting.
        let none_yaml = "\
services:
  isolated_job:
    image: alpine:latest
    network_mode: none
";
        let none_spec = parse_compose_yaml(none_yaml, &proj, Some("demo")).unwrap();
        assert!(!none_spec.networks.contains_key("default"));
        let none_payload =
            build_container_create_payload(&none_spec, &none_spec.services["isolated_job"]);
        assert_eq!(none_payload["HostConfig"]["NetworkMode"], "none");
        assert!(none_payload.get("NetworkingConfig").is_none());

        assert!(matches!(
            parse_compose_yaml(
                "services:\n  a:\n    image: alpine\n    network_mode: none\n    networks: [default]\n",
                &proj,
                Some("demo")
            ),
            Err(SandboxError::InvalidSpec(_))
        ));
        assert!(matches!(
            parse_compose_yaml(
                "services:\n  a:\n    image: alpine\n    network_mode: macvlan\n",
                &proj,
                Some("demo")
            ),
            Err(SandboxError::InvalidSpec(_))
        ));
        assert!(matches!(
            parse_compose_yaml(
                "services:\n  a:\n    image: alpine\n    container_name: same\n  b:\n    image: alpine\n    container_name: same\n",
                &proj,
                Some("demo")
            ),
            Err(SandboxError::InvalidSpec(_))
        ));

        fs::write(
            proj.join("quotes.env"),
            "SINGLE_STRIP=\"'inner'\"\nDBL=\"\"nested\"\"\nUNMATCHED=\"keep\n",
        )
        .unwrap();
        let env_spec = parse_compose_yaml(
            "services:\n  app:\n    image: alpine\n    env_file: quotes.env\n",
            &proj,
            Some("demo"),
        )
        .unwrap();
        let env = &env_spec.services["app"].env;
        assert_eq!(env["SINGLE_STRIP"], "'inner'");
        assert_eq!(env["DBL"], "\"nested\"");
        assert_eq!(env["UNMATCHED"], "\"keep");

        fs::write(proj.join("bad-key.env"), "=missing_key\n").unwrap();
        assert!(matches!(
            parse_compose_yaml(
                "services:\n  app:\n    image: alpine\n    env_file: bad-key.env\n",
                &proj,
                Some("demo")
            ),
            Err(SandboxError::InvalidSpec(_))
        ));

        let _ = fs::remove_dir_all(&tmp);
    }
}
