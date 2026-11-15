//! JSON payload rewriters for Docker container inspect and list responses.

use std::collections::{BTreeMap, HashSet};
use std::fmt;

use serde_json::{json, Map, Value};

use crate::ports::{ActivePortForward, PortForwardRegistry};

/// Error returned when a Podman inspect or list JSON payload cannot be parsed or rewritten.
#[derive(Debug)]
pub enum RewriteError {
    Json(serde_json::Error),
    InvalidShape(&'static str),
}

impl fmt::Display for RewriteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Json(err) => write!(f, "invalid JSON payload: {err}"),
            Self::InvalidShape(msg) => write!(f, "unexpected JSON shape: {msg}"),
        }
    }
}

impl std::error::Error for RewriteError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Json(err) => Some(err),
            Self::InvalidShape(_) => None,
        }
    }
}

impl From<serde_json::Error> for RewriteError {
    fn from(err: serde_json::Error) -> Self {
        Self::Json(err)
    }
}

/// Rewrites `NetworkSettings.Ports` and `HostConfig.PortBindings` in a Docker
/// `GET /containers/:id/json` response so clients see the Host loopback forward ports while
/// preserving all unrelated fields untouched.
pub fn rewrite_container_inspect_json(
    body: &[u8],
    forwards: &[ActivePortForward],
) -> Result<Vec<u8>, RewriteError> {
    let mut root: Value = serde_json::from_slice(body)?;
    let root_obj = root
        .as_object_mut()
        .ok_or(RewriteError::InvalidShape("inspect response must be a JSON object"))?;

    if forwards.is_empty() {
        return Ok(body.to_vec());
    }

    let mut grouped: BTreeMap<&str, Vec<Value>> = BTreeMap::new();
    for fwd in forwards {
        grouped.entry(fwd.container_key.as_str()).or_default().push(json!({
            "HostIp": fwd.host_ip,
            "HostPort": fwd.host_port.to_string(),
        }));
    }

    {
        let ns_obj = ensure_child_object(root_obj, "NetworkSettings", "NetworkSettings")?;
        let ns_ports = ensure_child_object(ns_obj, "Ports", "NetworkSettings.Ports")?;
        for (key, entries) in &grouped {
            ns_ports.insert((*key).to_owned(), Value::Array(entries.clone()));
        }
    }

    {
        let hc_obj = ensure_child_object(root_obj, "HostConfig", "HostConfig")?;
        let hc_bindings = ensure_child_object(hc_obj, "PortBindings", "HostConfig.PortBindings")?;
        for (key, entries) in grouped {
            hc_bindings.insert(key.to_owned(), Value::Array(entries));
        }
    }

    Ok(serde_json::to_vec(&root)?)
}

/// Rewrites `Ports` entries for every container in a Docker `GET /containers/json` array
/// response using active forwards in `registry`, preserving all other fields untouched.
pub fn rewrite_containers_list_json(
    body: &[u8],
    registry: &PortForwardRegistry,
) -> Result<Vec<u8>, RewriteError> {
    let mut root: Value = serde_json::from_slice(body)?;
    let items = root
        .as_array_mut()
        .ok_or(RewriteError::InvalidShape("container list response must be a JSON array"))?;

    for item in items.iter_mut() {
        let obj = item.as_object_mut().ok_or(RewriteError::InvalidShape(
            "container list entry must be a JSON object",
        ))?;

        let forwards = resolve_forwards_for_summary(obj, registry);
        if forwards.is_empty() {
            continue;
        }

        let replaced_keys: HashSet<(u16, &str)> = forwards
            .iter()
            .map(|f| (f.container_port, f.protocol.as_str()))
            .collect();

        let mut updated_ports = Vec::new();
        if let Some(existing) = obj.get("Ports").and_then(Value::as_array) {
            for entry in existing {
                let private_port = entry
                    .get("PrivatePort")
                    .and_then(Value::as_u64)
                    .and_then(|p| u16::try_from(p).ok());
                let proto = entry.get("Type").and_then(Value::as_str);
                let matches_forward = match (private_port, proto) {
                    (Some(port), Some(ty)) => replaced_keys.contains(&(port, ty)),
                    _ => false,
                };
                if !matches_forward {
                    updated_ports.push(entry.clone());
                }
            }
        }

        for fwd in forwards {
            updated_ports.push(json!({
                "IP": fwd.host_ip,
                "PrivatePort": fwd.container_port,
                "PublicPort": fwd.host_port,
                "Type": fwd.protocol,
            }));
        }

        obj.insert("Ports".to_owned(), Value::Array(updated_ports));
    }

    Ok(serde_json::to_vec(&root)?)
}

fn resolve_forwards_for_summary(
    obj: &Map<String, Value>,
    registry: &PortForwardRegistry,
) -> Vec<ActivePortForward> {
    if let Some(id) = obj.get("Id").and_then(Value::as_str) {
        let forwards = registry.snapshot_for_container(id);
        if !forwards.is_empty() {
            return forwards;
        }
    }
    if let Some(names) = obj.get("Names").and_then(Value::as_array) {
        for name_val in names {
            if let Some(name) = name_val.as_str() {
                let forwards = registry.snapshot_for_container(name);
                if !forwards.is_empty() {
                    return forwards;
                }
            }
        }
    }
    Vec::new()
}

fn ensure_child_object<'a>(
    parent: &'a mut Map<String, Value>,
    key: &str,
    label: &'static str,
) -> Result<&'a mut Map<String, Value>, RewriteError> {
    let replace_with_obj = match parent.get(key) {
        None => true,
        Some(v) => v.is_null(),
    };
    if replace_with_obj {
        parent.insert(key.to_owned(), Value::Object(Map::new()));
    }
    parent
        .get_mut(key)
        .and_then(Value::as_object_mut)
        .ok_or(RewriteError::InvalidShape(label))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::time::Duration;

    use crate::policy::RequestedPortBinding;
    use sandbox_core::{DestroyStatus, ExecRequest, SandboxError, SandboxId, SandboxLease, SandboxSpec};
    use sandbox_runtime::{ExecStream, RuntimeManager, SandboxTunnelPort, TunnelStream};

    struct NoopTunnel;

    #[async_trait::async_trait]
    impl RuntimeManager for NoopTunnel {
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
    impl SandboxTunnelPort for NoopTunnel {
        async fn open_podman_unix_stream(
            &self,
            _id: &SandboxId,
        ) -> Result<TunnelStream, SandboxError> {
            unreachable!()
        }
        async fn open_guest_tcp_stream(
            &self,
            _id: &SandboxId,
            _guest_port: u16,
        ) -> Result<TunnelStream, SandboxError> {
            unreachable!()
        }
    }

    #[test]
    fn rewrites_inspect_ports_and_host_config_while_preserving_other_fields() {
        let raw = serde_json::to_vec(&json!({
            "Id": "abc123",
            "Name": "/redis",
            "State": { "Running": true, "Pid": 42 },
            "Config": { "Image": "redis:7", "Labels": { "org.testcontainers": "true" } },
            "HostConfig": {
                "NetworkMode": "bridge",
                "PortBindings": {
                    "6379/tcp": [{ "HostIp": "127.0.0.1", "HostPort": "" }]
                }
            },
            "NetworkSettings": {
                "IPAddress": "10.88.0.2",
                "Ports": {
                    "6379/tcp": [{ "HostIp": "127.0.0.1", "HostPort": "45111" }],
                    "9000/tcp": null
                }
            }
        }))
        .unwrap();

        let forwards = vec![ActivePortForward {
            container_key: "6379/tcp".to_owned(),
            container_port: 6379,
            protocol: "tcp".to_owned(),
            host_ip: "127.0.0.1".to_owned(),
            host_port: 55678,
            guest_port: 45111,
        }];

        let rewritten = rewrite_container_inspect_json(&raw, &forwards).unwrap();
        let parsed: Value = serde_json::from_slice(&rewritten).unwrap();

        assert_eq!(parsed["Id"], "abc123");
        assert_eq!(parsed["Name"], "/redis");
        assert_eq!(parsed["State"]["Pid"], 42);
        assert_eq!(parsed["Config"]["Labels"]["org.testcontainers"], "true");
        assert_eq!(parsed["HostConfig"]["NetworkMode"], "bridge");
        assert_eq!(parsed["NetworkSettings"]["IPAddress"], "10.88.0.2");
        assert!(parsed["NetworkSettings"]["Ports"]["9000/tcp"].is_null());

        assert_eq!(
            parsed["NetworkSettings"]["Ports"]["6379/tcp"],
            json!([{ "HostIp": "127.0.0.1", "HostPort": "55678" }])
        );
        assert_eq!(
            parsed["HostConfig"]["PortBindings"]["6379/tcp"],
            json!([{ "HostIp": "127.0.0.1", "HostPort": "55678" }])
        );
    }

    #[tokio::test]
    async fn rewrites_containers_list_json_preserving_unpublished_ports_and_metadata() {
        let reg = PortForwardRegistry::new();
        let cid = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        reg.record_create(
            cid,
            Some("web-1"),
            vec![RequestedPortBinding {
                container_port: 8080,
                protocol: "tcp".to_owned(),
                host_port: None,
                container_key: "8080/tcp".to_owned(),
            }],
        );
        let inspect = json!({
            "Id": cid,
            "NetworkSettings": {
                "Ports": {
                    "8080/tcp": [{ "HostIp": "127.0.0.1", "HostPort": "49100" }]
                }
            }
        });
        let tunnel: Arc<dyn SandboxTunnelPort> = Arc::new(NoopTunnel);
        let forwards = reg
            .activate_container_forwards(tunnel, &SandboxId::new("sbx"), cid, &inspect)
            .await
            .unwrap();
        let actual_host_port = forwards[0].host_port;

        let list_raw = serde_json::to_vec(&json!([
            {
                "Id": cid,
                "Names": ["/web-1"],
                "Image": "nginx:alpine",
                "State": "running",
                "Labels": { "app": "demo" },
                "Ports": [
                    { "IP": "127.0.0.1", "PrivatePort": 8080, "PublicPort": 49100, "Type": "tcp" },
                    { "PrivatePort": 8443, "Type": "tcp" }
                ]
            },
            {
                "Id": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                "Names": ["/other"],
                "Ports": []
            }
        ]))
        .unwrap();

        let rewritten = rewrite_containers_list_json(&list_raw, &reg).unwrap();
        let parsed: Value = serde_json::from_slice(&rewritten).unwrap();

        assert_eq!(parsed[0]["Image"], "nginx:alpine");
        assert_eq!(parsed[0]["Labels"]["app"], "demo");
        assert_eq!(
            parsed[0]["Ports"],
            json!([
                { "PrivatePort": 8443, "Type": "tcp" },
                { "IP": "127.0.0.1", "PrivatePort": 8080, "PublicPort": actual_host_port, "Type": "tcp" }
            ])
        );
        assert_eq!(parsed[1]["Names"], json!(["/other"]));
        assert_eq!(parsed[1]["Ports"], json!([]));
    }
}
