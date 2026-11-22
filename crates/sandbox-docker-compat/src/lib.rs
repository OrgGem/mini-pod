#![forbid(unsafe_code)]
//! Layer 3 Docker API compatibility adapter boundary: host port forwarding over virtio,
//! inspect address/port rewriting, HTTP hijack/half-close, and unauthorized bind mount rejection.

pub mod hijack;
pub mod http1;
pub mod policy;
pub mod ports;
pub mod rewrite;
pub mod server;

pub use hijack::relay_upgraded;
pub use http1::{
    forward_body, read_body_bytes, read_request_head, read_response_head, write_json_error,
    write_request_head, write_response_head, BodyMode, HttpError, HttpRequestHead,
    HttpResponseHead, PrefixedReader, MAX_BUFFERED_BODY_BYTES, MAX_HEADER_BYTES,
};
pub use policy::{
    sanitize_container_create, sanitize_exec_create, sanitize_network_connect,
    sanitize_network_create, sanitize_volume_create, validate_image_build_query,
    validate_image_create_query, DockerCompatPolicy, PolicyRejection, ReaperSocketPolicy,
    RequestedPortBinding, SanitizedCreatePlan,
};
pub use ports::{ActivePortForward, PortForwardRegistry};
pub use rewrite::{rewrite_container_inspect_json, rewrite_containers_list_json, RewriteError};
#[cfg(windows)]
pub use server::NamedPipeServerHandle;
#[cfg(unix)]
pub use server::UnixServerHandle;
pub use server::DockerCompatServer;
