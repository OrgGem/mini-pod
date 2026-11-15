#![forbid(unsafe_code)]
//! Layer 3 Docker API compatibility adapter boundary: host port forwarding over virtio,
//! inspect address/port rewriting, HTTP hijack/half-close, and unauthorized bind mount rejection.

pub mod hijack;
pub mod http1;
pub mod policy;

pub use hijack::relay_upgraded;
pub use http1::{
    forward_body, read_body_bytes, read_request_head, read_response_head, write_json_error,
    write_request_head, write_response_head, BodyMode, HttpError, HttpRequestHead,
    HttpResponseHead, PrefixedReader, MAX_BUFFERED_BODY_BYTES, MAX_HEADER_BYTES,
};
pub use policy::{
    sanitize_container_create, DockerCompatPolicy, PolicyRejection, ReaperSocketPolicy,
    RequestedPortBinding, SanitizedCreatePlan,
};
