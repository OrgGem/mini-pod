//! MCP JSON-RPC 2.0 `stdio` server supporting both connected (`SandboxClient`) and
//! in-process standalone (`LocalRuntimeManager`) backends.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use sandbox_client::{ControlEndpoint, DaemonStatusInfo, SandboxClient};
use sandbox_core::{
    AccelerationPolicy, DestroyStatus, EgressRule, EnforcementLevel, ExecExitStatus, ExecRequest,
    ExecTarget, IsolationMode, NetworkPolicy, ResourceBudget, SandboxError, SandboxId, SandboxSpec,
};
use sandbox_runtime::{LocalRuntimeManager, RuntimeManager};
use serde_json::{json, Map, Value};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWrite, AsyncWriteExt, BufReader};

use crate::config::{McpConfig, McpMode};
use crate::server::{build_runtime, daemon_status_info};

const MCP_PROTOCOL_VERSION: &str = "2024-11-05";
const DEFAULT_EXEC_DEADLINE_SECS: u64 = 30;
const DEFAULT_EXEC_OUTPUT_BUDGET_BYTES: u64 = 1024 * 1024;

const JSONRPC_PARSE_ERROR: i64 = -32700;
const JSONRPC_INVALID_REQUEST: i64 = -32600;
const JSONRPC_METHOD_NOT_FOUND: i64 = -32601;
const JSONRPC_INVALID_PARAMS: i64 = -32602;

/// Unified execution backend for MCP tool calls.
pub enum McpBackend {
    Connected(SandboxClient),
    Standalone(Arc<LocalRuntimeManager>),
}

impl McpBackend {
    async fn status(&self) -> Result<DaemonStatusInfo, SandboxError> {
        match self {
            Self::Connected(client) => client.status().await,
            Self::Standalone(runtime) => Ok(daemon_status_info(runtime)),
        }
    }

    async fn spawn(&self, spec: SandboxSpec) -> Result<sandbox_core::SandboxLease, SandboxError> {
        match self {
            Self::Connected(client) => client.spawn(spec).await,
            Self::Standalone(runtime) => runtime.spawn(spec).await,
        }
    }

    async fn exec(
        &self,
        id: &SandboxId,
        req: ExecRequest,
        stdin: Option<Vec<u8>>,
    ) -> Result<(Vec<u8>, Vec<u8>, ExecExitStatus), SandboxError> {
        match self {
            Self::Connected(client) => {
                let stream = client.exec_stream(id, req).await?;
                if let Some(data) = stdin {
                    stream.write_stdin(data).await?;
                }
                let out = stream.collect().await?;
                Ok((out.stdout, out.stderr, out.exit))
            }
            Self::Standalone(runtime) => {
                let stream = runtime.exec_stream(id, req).await?;
                if let Some(data) = stdin {
                    stream.write_stdin(data).await?;
                }
                let out = stream.collect().await?;
                Ok((out.stdout, out.stderr, out.exit))
            }
        }
    }

    async fn renew_lease(&self, id: &SandboxId, ttl: Duration) -> Result<(), SandboxError> {
        match self {
            Self::Connected(client) => client.renew_lease(id, ttl).await,
            Self::Standalone(runtime) => runtime.renew_lease(id, ttl).await,
        }
    }

    async fn copy_in(
        &self,
        id: &SandboxId,
        src_host: &Path,
        dst_guest: &str,
    ) -> Result<(), SandboxError> {
        match self {
            Self::Connected(client) => client.copy_in_path(id, src_host, dst_guest).await,
            Self::Standalone(runtime) => {
                runtime
                    .copy_in(id, src_host.to_path_buf(), dst_guest.to_owned())
                    .await
            }
        }
    }

    async fn copy_out(
        &self,
        id: &SandboxId,
        src_guest: &str,
        dst_host: &Path,
    ) -> Result<(), SandboxError> {
        match self {
            Self::Connected(client) => {
                let _ = client.copy_out_to_path(id, src_guest, dst_host).await?;
                Ok(())
            }
            Self::Standalone(runtime) => {
                runtime
                    .copy_out(id, src_guest.to_owned(), dst_host.to_path_buf())
                    .await
            }
        }
    }

    async fn destroy(&self, id: &SandboxId) -> Result<DestroyStatus, SandboxError> {
        match self {
            Self::Connected(client) => client.destroy(id).await,
            Self::Standalone(runtime) => runtime.destroy(id).await,
        }
    }

    async fn shutdown_if_standalone(&self) {
        if let Self::Standalone(runtime) = self {
            let _ = runtime.drain_warm_pool().await;
            for id in runtime.active_sandbox_ids() {
                let _ = runtime.destroy(&id).await;
            }
        }
    }
}

/// Runs the MCP JSON-RPC 2.0 server over `stdin`/`stdout` (never emitting logs to `stdout`).
pub async fn run_mcp(cfg: McpConfig) -> Result<(), SandboxError> {
    let backend = match cfg.mode {
        McpMode::Connected(endpoint) => McpBackend::Connected(connect_client(endpoint)?),
        McpMode::Standalone(serve_cfg) => {
            let runtime = build_runtime(&serve_cfg).await?;
            McpBackend::Standalone(runtime)
        }
    };

    let stdin = BufReader::new(tokio::io::stdin());
    let stdout = tokio::io::stdout();
    let res = serve_mcp_stdio(stdin, stdout, &backend).await;
    backend.shutdown_if_standalone().await;
    res
}

fn connect_client(endpoint: ControlEndpoint) -> Result<SandboxClient, SandboxError> {
    endpoint.validate()?;
    Ok(SandboxClient::new(endpoint))
}

/// Processes newline-delimited JSON-RPC 2.0 requests from `reader` and writes responses to `writer`.
pub async fn serve_mcp_stdio<R, W>(
    mut reader: R,
    mut writer: W,
    backend: &McpBackend,
) -> Result<(), SandboxError>
where
    R: AsyncBufRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut line = String::new();
    loop {
        line.clear();
        let n = reader.read_line(&mut line).await.map_err(|err| {
            SandboxError::Transport(format!("failed reading MCP stdin line: {err}"))
        })?;
        if n == 0 {
            break;
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Some(resp) = handle_json_rpc_line(trimmed, backend).await {
            let serialized = serde_json::to_string(&resp).map_err(|err| {
                SandboxError::Internal(format!("failed serializing MCP JSON-RPC response: {err}"))
            })?;
            writer
                .write_all(serialized.as_bytes())
                .await
                .map_err(|err| {
                    SandboxError::Transport(format!("failed writing MCP response: {err}"))
                })?;
            writer.write_all(b"\n").await.map_err(|err| {
                SandboxError::Transport(format!("failed writing MCP response newline: {err}"))
            })?;
            writer.flush().await.map_err(|err| {
                SandboxError::Transport(format!("failed flushing MCP stdout: {err}"))
            })?;
        }
    }
    Ok(())
}

/// Evaluates a single JSON-RPC 2.0 message line, returning `None` for notifications.
pub async fn handle_json_rpc_line(line: &str, backend: &McpBackend) -> Option<Value> {
    let val: Value = match serde_json::from_str(line) {
        Ok(v) => v,
        Err(err) => {
            return Some(jsonrpc_error(
                Value::Null,
                JSONRPC_PARSE_ERROR,
                format!("Parse error: {err}"),
            ));
        }
    };

    let Some(obj) = val.as_object() else {
        return Some(jsonrpc_error(
            Value::Null,
            JSONRPC_INVALID_REQUEST,
            "Invalid Request: expected JSON object",
        ));
    };

    let id = match obj.get("id") {
        None => None,
        Some(v @ (Value::Null | Value::String(_) | Value::Number(_))) => Some(v.clone()),
        Some(_) => {
            return Some(jsonrpc_error(
                Value::Null,
                JSONRPC_INVALID_REQUEST,
                "Invalid Request: 'id' must be string, number, or null",
            ));
        }
    };

    let resp_id = id.clone().unwrap_or(Value::Null);

    if obj.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return Some(jsonrpc_error(
            resp_id,
            JSONRPC_INVALID_REQUEST,
            "Invalid Request: 'jsonrpc' must equal \"2.0\"",
        ));
    }

    let Some(method) = obj
        .get("method")
        .and_then(Value::as_str)
        .filter(|m| !m.is_empty())
    else {
        return Some(jsonrpc_error(
            resp_id,
            JSONRPC_INVALID_REQUEST,
            "Invalid Request: 'method' must be a non-empty string",
        ));
    };

    // Notifications (no `id`, or `notifications/*` lifecycle events) never receive a response.
    if id.is_none() || method.starts_with("notifications/") {
        return None;
    }

    let params = obj.get("params");
    match method {
        "initialize" => Some(json!({
            "jsonrpc": "2.0",
            "id": resp_id,
            "result": {
                "protocolVersion": MCP_PROTOCOL_VERSION,
                "capabilities": {
                    "tools": {
                        "listChanged": false
                    }
                },
                "serverInfo": {
                    "name": "minipod-sandboxd",
                    "version": env!("CARGO_PKG_VERSION"),
                }
            }
        })),
        "ping" => Some(json!({
            "jsonrpc": "2.0",
            "id": resp_id,
            "result": {}
        })),
        "tools/list" => Some(json!({
            "jsonrpc": "2.0",
            "id": resp_id,
            "result": {
                "tools": tool_definitions()
            }
        })),
        "tools/call" => Some(dispatch_tools_call(resp_id, params, backend).await),
        other => Some(jsonrpc_error(
            resp_id,
            JSONRPC_METHOD_NOT_FOUND,
            format!("Method not found: '{other}'"),
        )),
    }
}

async fn dispatch_tools_call(id: Value, params: Option<&Value>, backend: &McpBackend) -> Value {
    let Some(params_obj) = params.and_then(Value::as_object) else {
        return jsonrpc_error(
            id,
            JSONRPC_INVALID_PARAMS,
            "Invalid params: tools/call requires a params object",
        );
    };

    let Some(tool_name) = params_obj.get("name").and_then(Value::as_str) else {
        return jsonrpc_error(
            id,
            JSONRPC_INVALID_PARAMS,
            "Invalid params: tools/call requires string 'name'",
        );
    };

    let empty_map = Map::new();
    let args = match params_obj.get("arguments") {
        None | Some(Value::Null) => &empty_map,
        Some(Value::Object(map)) => map,
        Some(_) => {
            return jsonrpc_error(
                id,
                JSONRPC_INVALID_PARAMS,
                "Invalid params: 'arguments' must be a JSON object",
            );
        }
    };

    let outcome = match tool_name {
        "sandbox_status" => match execute_status(backend).await {
            Ok(val) => Ok(val),
            Err(err) => Err(err),
        },
        "sandbox_spawn" => {
            let spec = match parse_spawn_args(args) {
                Ok(s) => s,
                Err(msg) => return jsonrpc_error(id, JSONRPC_INVALID_PARAMS, msg),
            };
            execute_spawn(backend, spec).await
        }
        "sandbox_exec" => {
            let (sandbox_id, req, stdin) = match parse_exec_args(args) {
                Ok(parsed) => parsed,
                Err(msg) => return jsonrpc_error(id, JSONRPC_INVALID_PARAMS, msg),
            };
            execute_exec(backend, &sandbox_id, req, stdin).await
        }
        "sandbox_renew_lease" => {
            let (sandbox_id, ttl) = match parse_renew_args(args) {
                Ok(parsed) => parsed,
                Err(msg) => return jsonrpc_error(id, JSONRPC_INVALID_PARAMS, msg),
            };
            execute_renew(backend, &sandbox_id, ttl).await
        }
        "sandbox_copy_in" => {
            let (sandbox_id, src_host, dst_guest) = match parse_copy_in_args(args) {
                Ok(parsed) => parsed,
                Err(msg) => return jsonrpc_error(id, JSONRPC_INVALID_PARAMS, msg),
            };
            execute_copy_in(backend, &sandbox_id, &src_host, &dst_guest).await
        }
        "sandbox_copy_out" => {
            let (sandbox_id, src_guest, dst_host) = match parse_copy_out_args(args) {
                Ok(parsed) => parsed,
                Err(msg) => return jsonrpc_error(id, JSONRPC_INVALID_PARAMS, msg),
            };
            execute_copy_out(backend, &sandbox_id, &src_guest, &dst_host).await
        }
        "sandbox_destroy" => {
            let sandbox_id = match req_non_empty_str(args, "sandbox_id") {
                Ok(v) => SandboxId::new(v),
                Err(msg) => return jsonrpc_error(id, JSONRPC_INVALID_PARAMS, msg),
            };
            execute_destroy(backend, &sandbox_id).await
        }
        other => {
            return jsonrpc_error(
                id,
                JSONRPC_INVALID_PARAMS,
                format!("Invalid params: unknown tool '{other}'"),
            );
        }
    };

    match outcome {
        Ok(payload) => {
            let text = serde_json::to_string_pretty(&payload).unwrap_or_else(|_| payload.to_string());
            json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {
                    "content": [{
                        "type": "text",
                        "text": text,
                    }],
                    "isError": false,
                }
            })
        }
        Err(err) => json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": {
                "content": [{
                    "type": "text",
                    "text": err.to_string(),
                }],
                "isError": true,
            }
        }),
    }
}

async fn execute_status(backend: &McpBackend) -> Result<Value, SandboxError> {
    let info = backend.status().await?;
    Ok(json!({
        "active_sandboxes": info.active_sandboxes,
        "warm_ready_vms": info.warm_ready_vms,
        "effective_host_rss_mb": info.effective_host_rss_mb,
        "reserved_host_storage_mb": info.reserved_host_storage_mb,
        "version": info.version,
    }))
}

async fn execute_spawn(backend: &McpBackend, spec: SandboxSpec) -> Result<Value, SandboxError> {
    let lease = backend.spawn(spec).await?;
    Ok(json!({
        "id": lease.id.as_str(),
        "ttl_secs": lease.ttl.as_secs(),
        "capabilities": {
            "cpu_quota": enforcement_str(lease.capabilities.cpu_quota),
            "host_rss": enforcement_str(lease.capabilities.host_rss),
            "host_storage": enforcement_str(lease.capabilities.host_storage),
            "egress_filter": enforcement_str(lease.capabilities.egress_filter),
        }
    }))
}

async fn execute_exec(
    backend: &McpBackend,
    id: &SandboxId,
    req: ExecRequest,
    stdin: Option<Vec<u8>>,
) -> Result<Value, SandboxError> {
    let (stdout, stderr, exit) = backend.exec(id, req, stdin).await?;
    Ok(json!({
        "exit_code": exit.code,
        "timed_out": exit.timed_out,
        "stdout_truncated": exit.stdout_truncated,
        "stderr_truncated": exit.stderr_truncated,
        "stdout": String::from_utf8_lossy(&stdout),
        "stderr": String::from_utf8_lossy(&stderr),
    }))
}

async fn execute_renew(
    backend: &McpBackend,
    id: &SandboxId,
    ttl: Duration,
) -> Result<Value, SandboxError> {
    backend.renew_lease(id, ttl).await?;
    Ok(json!({
        "sandbox_id": id.as_str(),
        "renewed": true,
        "ttl_secs": ttl.as_secs(),
    }))
}

async fn execute_copy_in(
    backend: &McpBackend,
    id: &SandboxId,
    src_host: &Path,
    dst_guest: &str,
) -> Result<Value, SandboxError> {
    backend.copy_in(id, src_host, dst_guest).await?;
    Ok(json!({
        "sandbox_id": id.as_str(),
        "src_host": src_host.display().to_string(),
        "dst_guest": dst_guest,
        "copied": true,
    }))
}

async fn execute_copy_out(
    backend: &McpBackend,
    id: &SandboxId,
    src_guest: &str,
    dst_host: &Path,
) -> Result<Value, SandboxError> {
    backend.copy_out(id, src_guest, dst_host).await?;
    Ok(json!({
        "sandbox_id": id.as_str(),
        "src_guest": src_guest,
        "dst_host": dst_host.display().to_string(),
        "copied": true,
    }))
}

async fn execute_destroy(backend: &McpBackend, id: &SandboxId) -> Result<Value, SandboxError> {
    let status = backend.destroy(id).await?;
    let val = match status {
        DestroyStatus::AllResourcesCleaned => json!({
            "sandbox_id": id.as_str(),
            "status": "AllResourcesCleaned",
            "remaining_artifacts": [],
        }),
        DestroyStatus::ProcessExited { remaining_artifacts } => json!({
            "sandbox_id": id.as_str(),
            "status": "ProcessExited",
            "remaining_artifacts": remaining_artifacts
                .into_iter()
                .map(|p| p.display().to_string())
                .collect::<Vec<_>>(),
        }),
    };
    Ok(val)
}

fn parse_spawn_args(args: &Map<String, Value>) -> Result<SandboxSpec, String> {
    let isolation = match opt_str(args, "isolation")? {
        None | Some("vm") | Some("VmRequired") => IsolationMode::VmRequired,
        Some("shared-kernel") | Some("SharedKernelAllowed") => IsolationMode::SharedKernelAllowed,
        Some(other) => {
            return Err(format!(
                "Invalid params: unsupported isolation '{other}'; expected 'vm' or 'shared-kernel'"
            ));
        }
    };

    let acceleration = match opt_str(args, "acceleration")? {
        None | Some("preferred") | Some("Preferred") => AccelerationPolicy::Preferred,
        Some("required") | Some("Required") => AccelerationPolicy::Required,
        Some("software") | Some("SoftwareOnly") => AccelerationPolicy::SoftwareOnly,
        Some(other) => {
            return Err(format!(
                "Invalid params: unsupported acceleration '{other}'; expected 'required', 'preferred', or 'software'"
            ));
        }
    };

    let allow_rules = parse_allow_rules(args.get("allow_rules").or_else(|| args.get("rules")))?;
    let network = match opt_str(args, "network")? {
        None => match allow_rules {
            Some(rules) => NetworkPolicy::DomainAllowList { rules },
            None => NetworkPolicy::Isolated,
        },
        Some("isolated") | Some("Isolated") => {
            if allow_rules.is_some() {
                return Err(
                    "Invalid params: cannot specify 'allow_rules' when network='isolated'"
                        .to_owned(),
                );
            }
            NetworkPolicy::Isolated
        }
        Some("internet") | Some("InternetOnly") => {
            if allow_rules.is_some() {
                return Err(
                    "Invalid params: cannot specify 'allow_rules' when network='internet'"
                        .to_owned(),
                );
            }
            NetworkPolicy::InternetOnly
        }
        Some("unrestricted") | Some("Unrestricted") => {
            if allow_rules.is_some() {
                return Err(
                    "Invalid params: cannot specify 'allow_rules' when network='unrestricted'"
                        .to_owned(),
                );
            }
            NetworkPolicy::Unrestricted
        }
        Some("allowlist") | Some("DomainAllowList") => NetworkPolicy::DomainAllowList {
            rules: allow_rules.unwrap_or_default(),
        },
        Some(other) => {
            return Err(format!(
                "Invalid params: unsupported network '{other}'; expected 'isolated', 'internet', 'allowlist', or 'unrestricted'"
            ));
        }
    };

    let guest_vcpus = opt_u8(args, "vcpus")?.unwrap_or(1);
    let guest_ram_mb = opt_u32(args, "ram_mb")?.unwrap_or(256);
    let host_rss_budget_mb = opt_u32(args, "rss_mb")?;
    let host_cpu_quota_millicores = opt_u32(args, "cpu_millicores")?;
    let virtual_disk_mb = opt_u32(args, "disk_mb")?.unwrap_or(512);
    let host_storage_budget_mb = opt_u32(args, "storage_mb")?.unwrap_or(1024);
    let ttl_secs = opt_u64(args, "ttl_secs")?.unwrap_or(300);
    if ttl_secs == 0 {
        return Err("Invalid params: 'ttl_secs' must be greater than zero".to_owned());
    }

    let spec = SandboxSpec {
        isolation,
        acceleration,
        network,
        budget: ResourceBudget {
            guest_vcpus,
            host_cpu_quota_Millicores: host_cpu_quota_millicores,
            guest_ram_mb,
            host_rss_budget_mb,
            virtual_disk_mb,
            host_storage_budget_mb,
        },
        lease_ttl: Duration::from_secs(ttl_secs),
    };
    spec.validate_for_host_os(std::env::consts::OS)
        .map_err(|err| format!("Invalid params: {err}"))?;
    Ok(spec)
}

fn parse_allow_rules(val: Option<&Value>) -> Result<Option<Vec<EgressRule>>, String> {
    let Some(val) = val else {
        return Ok(None);
    };
    if val.is_null() {
        return Ok(None);
    }
    let arr = val
        .as_array()
        .ok_or_else(|| "Invalid params: 'allow_rules' must be an array".to_owned())?;
    let mut rules = Vec::with_capacity(arr.len());
    for item in arr {
        if let Some(s) = item.as_str() {
            let (domain, port_str) = s.rsplit_once(':').ok_or_else(|| {
                format!("Invalid params: rule '{s}' must have '<domain>:<port>' syntax")
            })?;
            let port: u16 = port_str.parse().map_err(|_| {
                format!("Invalid params: invalid port in rule '{s}'")
            })?;
            rules.push(EgressRule {
                domain: domain.to_owned(),
                port,
            });
        } else if let Some(obj) = item.as_object() {
            let domain = obj
                .get("domain")
                .and_then(Value::as_str)
                .filter(|d| !d.is_empty())
                .ok_or_else(|| "Invalid params: rule requires string 'domain'".to_owned())?;
            let port_u64 = obj
                .get("port")
                .and_then(Value::as_u64)
                .ok_or_else(|| "Invalid params: rule requires integer 'port'".to_owned())?;
            let port = u16::try_from(port_u64)
                .map_err(|_| "Invalid params: rule 'port' out of range".to_owned())?;
            rules.push(EgressRule {
                domain: domain.to_owned(),
                port,
            });
        } else {
            return Err("Invalid params: each allow_rules entry must be '<domain>:<port>' or {domain, port}".to_owned());
        }
    }
    Ok(Some(rules))
}

fn parse_exec_args(
    args: &Map<String, Value>,
) -> Result<(SandboxId, ExecRequest, Option<Vec<u8>>), String> {
    let sandbox_id = SandboxId::new(req_non_empty_str(args, "sandbox_id")?);
    let argv_val = args
        .get("argv")
        .and_then(Value::as_array)
        .ok_or_else(|| "Invalid params: 'argv' must be a non-empty array of strings".to_owned())?;
    if argv_val.is_empty() {
        return Err("Invalid params: 'argv' must not be empty".to_owned());
    }
    let mut argv = Vec::with_capacity(argv_val.len());
    for item in argv_val {
        let s = item
            .as_str()
            .ok_or_else(|| "Invalid params: every 'argv' element must be a string".to_owned())?;
        argv.push(s.to_owned());
    }

    let target = match opt_str(args, "container")? {
        Some("") => {
            return Err("Invalid params: 'container' must not be empty".to_owned());
        }
        Some(name) => ExecTarget::Container {
            id_or_name: name.to_owned(),
        },
        None => ExecTarget::Guest,
    };

    let cwd = opt_str(args, "cwd")?.map(str::to_owned);
    let user = opt_str(args, "user")?.map(str::to_owned);

    let mut env = BTreeMap::new();
    if let Some(env_val) = args.get("env") {
        if !env_val.is_null() {
            let env_obj = env_val
                .as_object()
                .ok_or_else(|| "Invalid params: 'env' must be an object".to_owned())?;
            for (k, v) in env_obj {
                let v_str = v.as_str().ok_or_else(|| {
                    format!("Invalid params: env['{k}'] must be a string")
                })?;
                env.insert(k.clone(), v_str.to_owned());
            }
        }
    }

    let stdin = opt_str(args, "stdin")?.map(|s| s.as_bytes().to_vec());
    let deadline_secs = opt_u64(args, "deadline_secs")?.unwrap_or(DEFAULT_EXEC_DEADLINE_SECS);
    if deadline_secs == 0 {
        return Err("Invalid params: 'deadline_secs' must be greater than zero".to_owned());
    }
    let stdout_budget_bytes =
        opt_u64(args, "stdout_budget_bytes")?.unwrap_or(DEFAULT_EXEC_OUTPUT_BUDGET_BYTES);
    let stderr_budget_bytes =
        opt_u64(args, "stderr_budget_bytes")?.unwrap_or(DEFAULT_EXEC_OUTPUT_BUDGET_BYTES);
    if stdout_budget_bytes == 0 || stderr_budget_bytes == 0 {
        return Err("Invalid params: output budgets must be greater than zero".to_owned());
    }

    let req = ExecRequest {
        target,
        argv,
        env,
        cwd,
        user,
        deadline: Duration::from_secs(deadline_secs),
        stdout_budget_bytes,
        stderr_budget_bytes,
    };
    Ok((sandbox_id, req, stdin))
}

fn parse_renew_args(args: &Map<String, Value>) -> Result<(SandboxId, Duration), String> {
    let sandbox_id = SandboxId::new(req_non_empty_str(args, "sandbox_id")?);
    let ttl_secs = args
        .get("ttl_secs")
        .and_then(Value::as_u64)
        .filter(|v| *v > 0)
        .ok_or_else(|| "Invalid params: 'ttl_secs' must be a positive integer".to_owned())?;
    Ok((sandbox_id, Duration::from_secs(ttl_secs)))
}

fn parse_copy_in_args(args: &Map<String, Value>) -> Result<(SandboxId, PathBuf, String), String> {
    let sandbox_id = SandboxId::new(req_non_empty_str(args, "sandbox_id")?);
    let src_host = PathBuf::from(req_non_empty_str(args, "src_host")?);
    let dst_guest = req_non_empty_str(args, "dst_guest")?.to_owned();
    Ok((sandbox_id, src_host, dst_guest))
}

fn parse_copy_out_args(args: &Map<String, Value>) -> Result<(SandboxId, String, PathBuf), String> {
    let sandbox_id = SandboxId::new(req_non_empty_str(args, "sandbox_id")?);
    let src_guest = req_non_empty_str(args, "src_guest")?.to_owned();
    let dst_host = PathBuf::from(req_non_empty_str(args, "dst_host")?);
    Ok((sandbox_id, src_guest, dst_host))
}

fn req_non_empty_str<'a>(args: &'a Map<String, Value>, key: &str) -> Result<&'a str, String> {
    args.get(key)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| format!("Invalid params: '{key}' must be a non-empty string"))
}

fn opt_str<'a>(args: &'a Map<String, Value>, key: &str) -> Result<Option<&'a str>, String> {
    match args.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => Ok(Some(s.as_str())),
        Some(_) => Err(format!("Invalid params: '{key}' must be a string")),
    }
}

fn opt_u8(args: &Map<String, Value>, key: &str) -> Result<Option<u8>, String> {
    match args.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(v) => v
            .as_u64()
            .and_then(|n| u8::try_from(n).ok())
            .map(Some)
            .ok_or_else(|| format!("Invalid params: '{key}' must be an integer 0..=255")),
    }
}

fn opt_u32(args: &Map<String, Value>, key: &str) -> Result<Option<u32>, String> {
    match args.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(v) => v
            .as_u64()
            .and_then(|n| u32::try_from(n).ok())
            .map(Some)
            .ok_or_else(|| format!("Invalid params: '{key}' must be an unsigned 32-bit integer")),
    }
}

fn opt_u64(args: &Map<String, Value>, key: &str) -> Result<Option<u64>, String> {
    match args.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(v) => v
            .as_u64()
            .map(Some)
            .ok_or_else(|| format!("Invalid params: '{key}' must be an unsigned 64-bit integer")),
    }
}

fn enforcement_str(level: EnforcementLevel) -> &'static str {
    match level {
        EnforcementLevel::HardLimit => "HardLimit",
        EnforcementLevel::BestEffort => "BestEffort",
        EnforcementLevel::Unsupported => "Unsupported",
    }
}

fn jsonrpc_error(id: Value, code: i64, message: impl Into<String>) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": code,
            "message": message.into(),
        }
    })
}

fn tool_definitions() -> Value {
    json!([
        {
            "name": "sandbox_status",
            "description": "Query mini-pod daemon active sandboxes, warm pool count, and host resource reservations.",
            "inputSchema": {
                "type": "object",
                "properties": {},
                "additionalProperties": false
            }
        },
        {
            "name": "sandbox_spawn",
            "description": "Spawn an isolated sandbox VM (or Linux shared-kernel sandbox when explicitly requested) with resource and egress policies.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "isolation": { "type": "string", "enum": ["vm", "shared-kernel"] },
                    "acceleration": { "type": "string", "enum": ["required", "preferred", "software"] },
                    "network": { "type": "string", "enum": ["isolated", "internet", "allowlist", "unrestricted"] },
                    "allow_rules": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "Domain allowlist rules in '<domain>:<port>' form"
                    },
                    "vcpus": { "type": "integer", "minimum": 1 },
                    "ram_mb": { "type": "integer", "minimum": 1 },
                    "rss_mb": { "type": "integer", "minimum": 1 },
                    "cpu_millicores": { "type": "integer", "minimum": 1 },
                    "disk_mb": { "type": "integer", "minimum": 1 },
                    "storage_mb": { "type": "integer", "minimum": 1 },
                    "ttl_secs": { "type": "integer", "minimum": 1 }
                }
            }
        },
        {
            "name": "sandbox_exec",
            "description": "Execute a command inside a sandbox guest OS or named container with bounded stdout/stderr and deadline.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "sandbox_id": { "type": "string" },
                    "argv": { "type": "array", "items": { "type": "string" }, "minItems": 1 },
                    "container": { "type": "string" },
                    "cwd": { "type": "string" },
                    "user": { "type": "string" },
                    "env": { "type": "object", "additionalProperties": { "type": "string" } },
                    "stdin": { "type": "string" },
                    "deadline_secs": { "type": "integer", "minimum": 1 },
                    "stdout_budget_bytes": { "type": "integer", "minimum": 1 },
                    "stderr_budget_bytes": { "type": "integer", "minimum": 1 }
                },
                "required": ["sandbox_id", "argv"]
            }
        },
        {
            "name": "sandbox_renew_lease",
            "description": "Extend an active sandbox lease TTL in seconds.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "sandbox_id": { "type": "string" },
                    "ttl_secs": { "type": "integer", "minimum": 1 }
                },
                "required": ["sandbox_id", "ttl_secs"]
            }
        },
        {
            "name": "sandbox_copy_in",
            "description": "Safely copy a host file or directory into a sandbox guest path via validated tar streaming.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "sandbox_id": { "type": "string" },
                    "src_host": { "type": "string" },
                    "dst_guest": { "type": "string" }
                },
                "required": ["sandbox_id", "src_host", "dst_guest"]
            }
        },
        {
            "name": "sandbox_copy_out",
            "description": "Safely copy files out from a sandbox guest path into a host directory.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "sandbox_id": { "type": "string" },
                    "src_guest": { "type": "string" },
                    "dst_host": { "type": "string" }
                },
                "required": ["sandbox_id", "src_guest", "dst_host"]
            }
        },
        {
            "name": "sandbox_destroy",
            "description": "Idempotently terminate a sandbox and clean up all host artifacts.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "sandbox_id": { "type": "string" }
                },
                "required": ["sandbox_id"]
            }
        }
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::fs;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::Mutex;

    use sandbox_core::CapabilityReport;
    use sandbox_protocol::{StreamId, StreamTargetWire};
    use sandbox_runtime::{
        AdmissionLimits, DiskOverlayPort, ExecOutputChunk, ExecStream, OutputStreamKind,
        PreparedOverlay, RuntimeManagerConfig, TunnelStream, VmBootConfig, VmBootOutcome,
        VmRuntimePort, VmSessionPort, WarmPoolConfig,
    };
    use tokio::io::duplex;
    use tokio::sync::mpsc;

    use crate::server::{serve_connection, DaemonState};

    static MCP_TEST_SEQ: AtomicU64 = AtomicU64::new(0);

    struct TestTempDir(PathBuf);

    impl TestTempDir {
        fn new(label: &str) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "minipod-mcp-test-{label}-{}-{}",
                std::process::id(),
                MCP_TEST_SEQ.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir_all(&dir).unwrap();
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

    struct McpStubOverlay;

    #[async_trait::async_trait]
    impl DiskOverlayPort for McpStubOverlay {
        async fn prepare_overlay(
            &self,
            _sandbox_id: &SandboxId,
            spec: &SandboxSpec,
            work_dir: &Path,
        ) -> Result<PreparedOverlay, SandboxError> {
            let overlay_path = work_dir.join("overlay.qcow2");
            fs::write(&overlay_path, b"qcow2").unwrap();
            Ok(PreparedOverlay {
                overlay_path,
                kernel_path: PathBuf::from("/vmlinuz"),
                initramfs_path: PathBuf::from("/initrd"),
                rootfs_path: PathBuf::from("/rootfs.qcow2"),
                kernel_cmdline: "quiet".to_owned(),
                virtual_disk_mb: spec.budget.virtual_disk_mb,
                provisioned_host_bytes: 5,
            })
        }

        async fn remove_overlay(&self, overlay_path: &Path) -> Result<(), SandboxError> {
            if overlay_path.exists() {
                let _ = fs::remove_file(overlay_path);
            }
            Ok(())
        }
    }

    struct McpStubSession {
        pid: u32,
        alive: AtomicBool,
        tar_store: Mutex<Option<Vec<u8>>>,
    }

    #[async_trait::async_trait]
    impl VmSessionPort for McpStubSession {
        fn pid(&self) -> u32 {
            self.pid
        }
        fn start_token(&self) -> u64 {
            1
        }
        fn artifact_paths(&self) -> &[PathBuf] {
            &[]
        }
        fn is_alive(&self) -> bool {
            self.alive.load(Ordering::Acquire)
        }
        fn current_rss_bytes(&self) -> Option<u64> {
            Some(64 * 1024 * 1024)
        }

        async fn exec_stream(&self, req: ExecRequest) -> Result<ExecStream, SandboxError> {
            let (stream, mut handle) = ExecStream::channel(StreamId(1));
            tokio::spawn(async move {
                let mut stdin_bytes = Vec::new();
                while let Some(chunk) = handle.recv_stdin().await {
                    stdin_bytes.extend_from_slice(&chunk);
                }
                let _ = handle
                    .send_output(ExecOutputChunk {
                        stream: OutputStreamKind::Stdout,
                        data: [req.argv.join(" ").as_bytes(), b":", &stdin_bytes].concat(),
                    })
                    .await;
                handle.finish(Ok(ExecExitStatus {
                    code: Some(0),
                    timed_out: false,
                    stdout_truncated: false,
                    stderr_truncated: false,
                }));
            });
            Ok(stream)
        }

        async fn open_tunnel(&self, _target: StreamTargetWire) -> Result<TunnelStream, SandboxError> {
            let (client, _h) = TunnelStream::channel(StreamId(3));
            Ok(client)
        }

        async fn enable_egress_proxy(
            &self,
            _proxy_port: u16,
        ) -> Result<mpsc::Receiver<TunnelStream>, SandboxError> {
            let (_tx, rx) = mpsc::channel(2);
            Ok(rx)
        }

        async fn copy_in_tar(
            &self,
            _dst_guest: &str,
            tar_bytes: Vec<u8>,
            _max_bytes: u64,
        ) -> Result<u64, SandboxError> {
            let len = tar_bytes.len() as u64;
            *self.tar_store.lock().unwrap() = Some(tar_bytes);
            Ok(len)
        }

        async fn copy_out_tar(
            &self,
            _src_guest: &str,
            _max_bytes: u64,
        ) -> Result<Vec<u8>, SandboxError> {
            Ok(self.tar_store.lock().unwrap().clone().unwrap_or_default())
        }

        async fn graceful_shutdown(&self, _timeout: Duration) -> Result<bool, SandboxError> {
            self.alive.store(false, Ordering::Release);
            Ok(true)
        }

        async fn force_kill(&self) -> Result<(), SandboxError> {
            self.alive.store(false, Ordering::Release);
            Ok(())
        }
    }

    struct McpStubVmRuntime {
        next_pid: AtomicU64,
    }

    #[async_trait::async_trait]
    impl VmRuntimePort for McpStubVmRuntime {
        async fn boot_vm(&self, _config: VmBootConfig) -> Result<VmBootOutcome, SandboxError> {
            let pid = self.next_pid.fetch_add(1, Ordering::Relaxed) as u32;
            Ok(VmBootOutcome {
                session: Box::new(McpStubSession {
                    pid,
                    alive: AtomicBool::new(true),
                    tar_store: Mutex::new(None),
                }),
                pid,
                start_token: 1,
                artifact_paths: Vec::new(),
                hardware_accelerated: true,
                capabilities: CapabilityReport {
                    cpu_quota: EnforcementLevel::HardLimit,
                    host_rss: EnforcementLevel::BestEffort,
                    host_storage: EnforcementLevel::HardLimit,
                    egress_filter: EnforcementLevel::HardLimit,
                },
                egress_rx: None,
            })
        }

        async fn kill_orphan_process(
            &self,
            _pid: u32,
            _expected_start_token: u64,
        ) -> Result<bool, SandboxError> {
            Ok(false)
        }
    }

    fn build_runtime_for_test(tmp: &TestTempDir) -> Arc<LocalRuntimeManager> {
        let rt_cfg = RuntimeManagerConfig {
            state_dir: tmp.path().join("state"),
            sweep_interval: Duration::from_secs(10),
            graceful_shutdown_timeout: Duration::from_millis(50),
            max_copy_bytes: 8 * 1024 * 1024,
            max_copy_entries: 1024,
            cleanup_max_attempts: 3,
            cleanup_initial_delay: Duration::from_millis(5),
            admission: AdmissionLimits::default(),
            warm_pool: WarmPoolConfig::default(),
        };
        Arc::new(
            LocalRuntimeManager::new(
                rt_cfg,
                Arc::new(McpStubOverlay),
                Arc::new(McpStubVmRuntime {
                    next_pid: AtomicU64::new(500),
                }),
            )
            .unwrap(),
        )
    }

    async fn run_full_mcp_script(backend: &McpBackend, tmp: &TestTempDir) {
        let src_dir = tmp.path().join("mcp-in");
        fs::create_dir_all(&src_dir).unwrap();
        fs::write(src_dir.join("note.txt"), b"mcp-file").unwrap();
        let dst_dir = tmp.path().join("mcp-out");

        let script = [
            // Invalid JSON -> -32700
            "{broken".to_owned(),
            // Invalid request -> -32600
            json!({"jsonrpc": "1.0", "id": 1, "method": "ping"}).to_string(),
            // Initialize
            json!({"jsonrpc": "2.0", "id": 2, "method": "initialize", "params": {"protocolVersion": "2024-11-05"}}).to_string(),
            // Notification -> silent (no response)
            json!({"jsonrpc": "2.0", "method": "notifications/initialized"}).to_string(),
            // Ping + unknown method (-32601) + unknown tool (-32602) + invalid params (-32602)
            json!({"jsonrpc": "2.0", "id": 3, "method": "ping"}).to_string(),
            json!({"jsonrpc": "2.0", "id": 4, "method": "unknown/method"}).to_string(),
            json!({"jsonrpc": "2.0", "id": 5, "method": "tools/list"}).to_string(),
            json!({"jsonrpc": "2.0", "id": 6, "method": "tools/call", "params": {"name": "no_such_tool"}}).to_string(),
            json!({"jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": {"name": "sandbox_renew_lease", "arguments": {"sandbox_id": "sb", "ttl_secs": 0}}}).to_string(),
            // Status before spawn
            json!({"jsonrpc": "2.0", "id": 8, "method": "tools/call", "params": {"name": "sandbox_status"}}).to_string(),
            // Spawn
            json!({"jsonrpc": "2.0", "id": 9, "method": "tools/call", "params": {"name": "sandbox_spawn", "arguments": {"ttl_secs": 60}}}).to_string(),
        ]
        .join("\n")
            + "\n";

        let mut output = Vec::new();
        serve_mcp_stdio(BufReader::new(script.as_bytes()), &mut output, backend)
            .await
            .unwrap();

        let lines: Vec<Value> = String::from_utf8(output)
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();

        // 11 lines sent, 1 notification -> 10 responses.
        assert_eq!(lines.len(), 10);
        assert_eq!(lines[0]["error"]["code"], JSONRPC_PARSE_ERROR);
        assert_eq!(lines[1]["error"]["code"], JSONRPC_INVALID_REQUEST);
        assert_eq!(lines[2]["id"], 2);
        assert_eq!(lines[2]["result"]["protocolVersion"], "2024-11-05");
        assert_eq!(lines[3]["id"], 3);
        assert_eq!(lines[3]["result"], json!({}));
        assert_eq!(lines[4]["id"], 4);
        assert_eq!(lines[4]["error"]["code"], JSONRPC_METHOD_NOT_FOUND);
        assert_eq!(lines[5]["id"], 5);
        assert_eq!(lines[5]["result"]["tools"].as_array().unwrap().len(), 7);
        assert_eq!(lines[6]["id"], 6);
        assert_eq!(lines[6]["error"]["code"], JSONRPC_INVALID_PARAMS);
        assert_eq!(lines[7]["id"], 7);
        assert_eq!(lines[7]["error"]["code"], JSONRPC_INVALID_PARAMS);

        let status_payload: Value =
            serde_json::from_str(lines[8]["result"]["content"][0]["text"].as_str().unwrap())
                .unwrap();
        assert_eq!(status_payload["active_sandboxes"], 0);

        let spawn_payload: Value =
            serde_json::from_str(lines[9]["result"]["content"][0]["text"].as_str().unwrap())
                .unwrap();
        let sandbox_id = spawn_payload["id"].as_str().unwrap().to_owned();

        let mut step2 = String::new();
        for req in [
            json!({"jsonrpc": "2.0", "id": 10, "method": "tools/call", "params": {"name": "sandbox_renew_lease", "arguments": {"sandbox_id": sandbox_id, "ttl_secs": 120}}}),
            json!({"jsonrpc": "2.0", "id": 11, "method": "tools/call", "params": {"name": "sandbox_exec", "arguments": {"sandbox_id": sandbox_id, "argv": ["echo", "ok"], "stdin": "in"}}}),
            json!({"jsonrpc": "2.0", "id": 12, "method": "tools/call", "params": {"name": "sandbox_copy_in", "arguments": {"sandbox_id": sandbox_id, "src_host": src_dir.display().to_string(), "dst_guest": "/workspace"}}}),
            json!({"jsonrpc": "2.0", "id": 13, "method": "tools/call", "params": {"name": "sandbox_copy_out", "arguments": {"sandbox_id": sandbox_id, "src_guest": "/workspace", "dst_host": dst_dir.display().to_string()}}}),
            json!({"jsonrpc": "2.0", "id": 14, "method": "tools/call", "params": {"name": "sandbox_destroy", "arguments": {"sandbox_id": sandbox_id}}}),
            // Calling exec on destroyed sandbox returns tool result with isError: true.
            json!({"jsonrpc": "2.0", "id": 15, "method": "tools/call", "params": {"name": "sandbox_exec", "arguments": {"sandbox_id": sandbox_id, "argv": ["echo"]}}}),
        ] {
            step2.push_str(&req.to_string());
            step2.push('\n');
        }

        let mut out2 = Vec::new();
        serve_mcp_stdio(BufReader::new(step2.as_bytes()), &mut out2, backend)
            .await
            .unwrap();
        let lines2: Vec<Value> = String::from_utf8(out2)
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();

        assert_eq!(lines2.len(), 6);
        assert_eq!(lines2[0]["result"]["isError"], false);
        let exec_payload: Value =
            serde_json::from_str(lines2[1]["result"]["content"][0]["text"].as_str().unwrap())
                .unwrap();
        assert_eq!(exec_payload["exit_code"], 0);
        assert_eq!(exec_payload["stdout"], "echo ok:in");
        assert_eq!(lines2[2]["result"]["isError"], false);
        assert_eq!(lines2[3]["result"]["isError"], false);
        assert_eq!(fs::read(dst_dir.join("note.txt")).unwrap(), b"mcp-file");
        assert_eq!(lines2[4]["result"]["isError"], false);
        assert_eq!(lines2[5]["result"]["isError"], true);
    }

    #[tokio::test]
    async fn mcp_standalone_and_connected_dispatch_all_tools_and_errors() {
        let tmp_standalone = TestTempDir::new("standalone");
        let rt_standalone = build_runtime_for_test(&tmp_standalone);
        run_full_mcp_script(&McpBackend::Standalone(rt_standalone), &tmp_standalone).await;

        let tmp_connected = TestTempDir::new("connected");
        let rt_connected = build_runtime_for_test(&tmp_connected);
        let daemon_state = Arc::new(DaemonState::new(rt_connected));
        let ep = if cfg!(windows) {
            ControlEndpoint::NamedPipe(r"\\.\pipe\mcp-test-duplex".to_owned())
        } else {
            ControlEndpoint::UnixSocket(PathBuf::from("/tmp/mcp-test-duplex.sock"))
        };
        let client = SandboxClient::with_connector(ep, move |_| {
            let st = Arc::clone(&daemon_state);
            async move {
                let (c, s) = duplex(1024 * 1024);
                tokio::spawn(async move {
                    let _ = serve_connection(s, st).await;
                });
                Ok(c)
            }
        });
        run_full_mcp_script(&McpBackend::Connected(client), &tmp_connected).await;
    }
}
