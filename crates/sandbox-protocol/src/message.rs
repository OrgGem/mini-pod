//! Typed protocol messages and strict binary payload codecs.

use std::collections::BTreeMap;

use crate::{check_payload_len, FrameKind, Lane, ProtocolError, MAX_FRAME_PAYLOAD_BYTES};

/// Execution target inside a sandboxed guest (`Guest` OS vs a named/ID'd `Container`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExecTargetWire {
    Guest,
    Container { id_or_name: String },
}

/// Target stream endpoint inside a sandboxed guest for multiplexed host-to-guest tunnels.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StreamTargetWire {
    PodmanUnixSocket,
    GuestLoopbackTcp { port: u16 },
}

/// Guest I/O stream multiplexed over `Message::StreamData` and `Message::StreamCredit`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum StreamChannel {
    Stdin = 0,
    Stdout = 1,
    Stderr = 2,
}

impl TryFrom<u8> for StreamChannel {
    type Error = ProtocolError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Stdin),
            1 => Ok(Self::Stdout),
            2 => Ok(Self::Stderr),
            other => Err(ProtocolError::InvalidPayload(format!(
                "invalid stream channel byte: {other}"
            ))),
        }
    }
}

/// Typed control and data payloads exchanged over framed `virtio-serial` / `virtio-vsock` streams.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Message {
    /// Initiates protocol version negotiation from host to guest agent.
    Hello { version: u8 },
    /// Confirms negotiated version and bitmask of enabled agent features.
    HelloAck { version: u8, features: u32 },
    /// Starts an execution process inside the guest OS or guest container with non-empty `argv`.
    ExecStart {
        target: ExecTargetWire,
        argv: Vec<String>,
        env: BTreeMap<String, String>,
        cwd: Option<String>,
        user: Option<String>,
        deadline_ms: u64,
        stdout_budget_bytes: u64,
        stderr_budget_bytes: u64,
    },
    /// Carries raw bytes or EOF for stdin/stdout/stderr (or tar copy chunks) on a `StreamId`.
    StreamData {
        channel: StreamChannel,
        eof: bool,
        data: Vec<u8>,
    },
    /// Grants `bytes` of send window credit for flow-controlled stream backpressure.
    StreamCredit { channel: StreamChannel, bytes: u32 },
    /// Requests immediate cancellation of an in-flight execution.
    ExecCancel,
    /// Reports final process exit status and budget truncation flags after stream termination.
    ///
    /// Classified on [`Lane::Control`]: senders must only enqueue/transmit `ExecExit` after all
    /// `StreamData` chunks (including `eof: true` on stdout/stderr) for that `StreamId` have
    /// drained from outbound queues.
    ExecExit {
        code: Option<i32>,
        timed_out: bool,
        stdout_truncated: bool,
        stderr_truncated: bool,
    },
    /// Liveness probe carrying caller sequence number.
    Ping { seq: u64 },
    /// Liveness response echoing the `Ping` sequence number.
    Pong { seq: u64 },
    /// Requests graceful guest agent shutdown.
    Shutdown,
    /// Initiates a host-to-guest tar copy-in transfer to `dst_guest` bounded by `max_bytes`.
    ///
    /// Raw tar archive chunks travel on the same `StreamId` as `StreamData` frames on
    /// [`StreamChannel::Stdin`] terminated by `eof: true` (flow-controlled via [`Message::StreamCredit`]).
    /// Once all chunks up to `eof: true` are processed, the guest responds on the same `StreamId`
    /// with [`Message::CopyDone`] or [`Message::CopyError`].
    CopyInStart {
        dst_guest: String,
        max_bytes: u64,
    },
    /// Initiates a guest-to-host tar copy-out transfer from `src_guest` bounded by `max_bytes`.
    ///
    /// Guest streams raw tar archive chunks on the same `StreamId` via `StreamData` on
    /// [`StreamChannel::Stdout`] terminated by `eof: true`, followed by [`Message::CopyDone`]
    /// (on [`Lane::Data`] so it never overtakes tar chunks in [`crate::PriorityFrameQueue`]) or
    /// [`Message::CopyError`] (on [`Lane::Control`]).
    CopyOutStart {
        src_guest: String,
        max_bytes: u64,
    },
    /// Confirms completion of a tar copy transfer after all `StreamData` chunks have been emitted.
    ///
    /// Classified on [`Lane::Data`] so [`crate::PriorityFrameQueue`] preserves strict FIFO order
    /// after `StreamData` tar chunks during `CopyOut`, while [`Message::CopyError`] and
    /// [`Message::StreamCredit`] keep urgent [`Lane::Control`] priority.
    CopyDone {
        bytes_transferred: u64,
    },
    /// Reports failure of an in-flight tar copy-in or copy-out transfer on [`Lane::Control`].
    CopyError {
        message: String,
    },
    /// Requests opening a multiplexed stream tunnel to the guest Podman socket or loopback TCP port.
    ConnectStart {
        target: StreamTargetWire,
    },
    /// Confirms that the guest tunnel target connection succeeded and streaming may proceed.
    ConnectAck,
    /// Reports failure establishing or sustaining a guest tunnel connection on [`Lane::Control`].
    ConnectError {
        message: String,
    },
    /// Aborts or closes both directions of an active tunnel stream immediately on [`Lane::Control`].
    StreamClose,
    /// Configures the guest egress proxy listener (`StreamId(0)`, [`Lane::Control`]).
    ConfigureNetwork {
        enable_egress_proxy: bool,
        proxy_port: u16,
    },
    /// Confirms guest network configuration and reports the actual bound port (`0` when disabled).
    ConfigureNetworkAck { proxy_port: u16 },
    /// Announces a newly accepted guest egress proxy TCP connection on a guest-allocated `StreamId`.
    EgressOpen,
}

impl Message {
    /// Returns the priority lane required for this message (`Control` vs `Data`).
    pub fn lane(&self) -> Lane {
        self.kind().lane()
    }

    /// Returns the wire `FrameKind` discriminant corresponding to this message variant.
    pub fn kind(&self) -> FrameKind {
        match self {
            Self::Hello { .. } => FrameKind::Hello,
            Self::HelloAck { .. } => FrameKind::HelloAck,
            Self::ExecStart { .. } => FrameKind::ExecStart,
            Self::StreamData { .. } => FrameKind::StreamData,
            Self::StreamCredit { .. } => FrameKind::StreamCredit,
            Self::ExecCancel => FrameKind::ExecCancel,
            Self::ExecExit { .. } => FrameKind::ExecExit,
            Self::Ping { .. } => FrameKind::Ping,
            Self::Pong { .. } => FrameKind::Pong,
            Self::Shutdown => FrameKind::Shutdown,
            Self::CopyInStart { .. } => FrameKind::CopyInStart,
            Self::CopyOutStart { .. } => FrameKind::CopyOutStart,
            Self::CopyDone { .. } => FrameKind::CopyDone,
            Self::CopyError { .. } => FrameKind::CopyError,
            Self::ConnectStart { .. } => FrameKind::ConnectStart,
            Self::ConnectAck => FrameKind::ConnectAck,
            Self::ConnectError { .. } => FrameKind::ConnectError,
            Self::StreamClose => FrameKind::StreamClose,
            Self::ConfigureNetwork { .. } => FrameKind::ConfigureNetwork,
            Self::ConfigureNetworkAck { .. } => FrameKind::ConfigureNetworkAck,
            Self::EgressOpen => FrameKind::EgressOpen,
        }
    }

    /// Encodes this message's payload into big-endian wire bytes within `MAX_FRAME_PAYLOAD_BYTES`.
    pub fn encode_payload(&self) -> Result<Vec<u8>, ProtocolError> {
        match self {
            Self::Hello { version } => Ok(vec![*version]),
            Self::HelloAck { version, features } => {
                let mut writer = PayloadWriter::with_capacity(5)?;
                writer.write_u8(*version)?;
                writer.write_u32(*features)?;
                Ok(writer.finish())
            }
            Self::ExecStart {
                target,
                argv,
                env,
                cwd,
                user,
                deadline_ms,
                stdout_budget_bytes,
                stderr_budget_bytes,
            } => encode_exec_start(
                target,
                argv,
                env,
                cwd.as_deref(),
                user.as_deref(),
                *deadline_ms,
                *stdout_budget_bytes,
                *stderr_budget_bytes,
            ),
            Self::StreamData { channel, eof, data } => {
                let total = 2usize
                    .checked_add(data.len())
                    .ok_or(ProtocolError::PayloadTooLarge {
                        len: u32::MAX,
                        max: MAX_FRAME_PAYLOAD_BYTES,
                    })?;
                let mut writer = PayloadWriter::with_capacity(total)?;
                writer.write_u8(*channel as u8)?;
                writer.write_bool(*eof)?;
                writer.write_bytes(data)?;
                Ok(writer.finish())
            }
            Self::StreamCredit { channel, bytes } => {
                let mut writer = PayloadWriter::with_capacity(5)?;
                writer.write_u8(*channel as u8)?;
                writer.write_u32(*bytes)?;
                Ok(writer.finish())
            }
            Self::ExecCancel
            | Self::Shutdown
            | Self::ConnectAck
            | Self::StreamClose
            | Self::EgressOpen => Ok(Vec::new()),
            Self::ExecExit {
                code,
                timed_out,
                stdout_truncated,
                stderr_truncated,
            } => {
                let mut writer = PayloadWriter::with_capacity(if code.is_some() { 8 } else { 4 })?;
                writer.write_opt_i32(*code)?;
                writer.write_bool(*timed_out)?;
                writer.write_bool(*stdout_truncated)?;
                writer.write_bool(*stderr_truncated)?;
                Ok(writer.finish())
            }
            Self::Ping { seq } | Self::Pong { seq } => Ok(seq.to_be_bytes().to_vec()),
            Self::CopyInStart {
                dst_guest,
                max_bytes,
            } => {
                let mut writer = PayloadWriter::new();
                writer.write_str(dst_guest)?;
                writer.write_u64(*max_bytes)?;
                Ok(writer.finish())
            }
            Self::CopyOutStart {
                src_guest,
                max_bytes,
            } => {
                let mut writer = PayloadWriter::new();
                writer.write_str(src_guest)?;
                writer.write_u64(*max_bytes)?;
                Ok(writer.finish())
            }
            Self::CopyDone { bytes_transferred } => Ok(bytes_transferred.to_be_bytes().to_vec()),
            Self::CopyError { message } | Self::ConnectError { message } => {
                let mut writer = PayloadWriter::new();
                writer.write_str(message)?;
                Ok(writer.finish())
            }
            Self::ConnectStart { target } => {
                let cap = match target {
                    StreamTargetWire::PodmanUnixSocket => 1,
                    StreamTargetWire::GuestLoopbackTcp { .. } => 3,
                };
                let mut writer = PayloadWriter::with_capacity(cap)?;
                match target {
                    StreamTargetWire::PodmanUnixSocket => writer.write_u8(0)?,
                    StreamTargetWire::GuestLoopbackTcp { port } => {
                        if *port == 0 {
                            return Err(ProtocolError::InvalidPayload(
                                "ConnectStart GuestLoopbackTcp port must be nonzero".to_owned(),
                            ));
                        }
                        writer.write_u8(1)?;
                        writer.write_u16(*port)?;
                    }
                }
                Ok(writer.finish())
            }
            Self::ConfigureNetwork {
                enable_egress_proxy,
                proxy_port,
            } => {
                if *enable_egress_proxy && *proxy_port == 0 {
                    return Err(ProtocolError::InvalidPayload(
                        "ConfigureNetwork proxy_port must be nonzero when egress proxy is enabled"
                            .to_owned(),
                    ));
                }
                let mut writer = PayloadWriter::with_capacity(3)?;
                writer.write_bool(*enable_egress_proxy)?;
                writer.write_u16(*proxy_port)?;
                Ok(writer.finish())
            }
            Self::ConfigureNetworkAck { proxy_port } => Ok(proxy_port.to_be_bytes().to_vec()),
        }
    }

    /// Strictly decodes a `Message` for `kind` from `payload`, rejecting malformed or trailing bytes.
    pub fn decode(kind: FrameKind, payload: &[u8]) -> Result<Self, ProtocolError> {
        check_payload_len(payload.len())?;
        let mut reader = PayloadReader::new(payload);
        let msg = match kind {
            FrameKind::Hello => Self::Hello {
                version: reader.read_u8()?,
            },
            FrameKind::HelloAck => Self::HelloAck {
                version: reader.read_u8()?,
                features: reader.read_u32()?,
            },
            FrameKind::ExecStart => decode_exec_start(&mut reader)?,
            FrameKind::StreamData => {
                let channel = StreamChannel::try_from(reader.read_u8()?)?;
                let eof = reader.read_bool("StreamData.eof")?;
                let data = reader.take_rest().to_vec();
                return Ok(Self::StreamData { channel, eof, data });
            }
            FrameKind::StreamCredit => Self::StreamCredit {
                channel: StreamChannel::try_from(reader.read_u8()?)?,
                bytes: reader.read_u32()?,
            },
            FrameKind::ExecCancel => Self::ExecCancel,
            FrameKind::ExecExit => Self::ExecExit {
                code: reader.read_opt_i32("ExecExit.code")?,
                timed_out: reader.read_bool("ExecExit.timed_out")?,
                stdout_truncated: reader.read_bool("ExecExit.stdout_truncated")?,
                stderr_truncated: reader.read_bool("ExecExit.stderr_truncated")?,
            },
            FrameKind::Ping => Self::Ping {
                seq: reader.read_u64()?,
            },
            FrameKind::Pong => Self::Pong {
                seq: reader.read_u64()?,
            },
            FrameKind::Shutdown => Self::Shutdown,
            FrameKind::CopyInStart => Self::CopyInStart {
                dst_guest: reader.read_str()?,
                max_bytes: reader.read_u64()?,
            },
            FrameKind::CopyOutStart => Self::CopyOutStart {
                src_guest: reader.read_str()?,
                max_bytes: reader.read_u64()?,
            },
            FrameKind::CopyDone => Self::CopyDone {
                bytes_transferred: reader.read_u64()?,
            },
            FrameKind::CopyError => Self::CopyError {
                message: reader.read_str()?,
            },
            FrameKind::ConnectStart => {
                let target = match reader.read_u8()? {
                    0 => StreamTargetWire::PodmanUnixSocket,
                    1 => {
                        let port = reader.read_u16()?;
                        if port == 0 {
                            return Err(ProtocolError::InvalidPayload(
                                "ConnectStart GuestLoopbackTcp port must be nonzero".to_owned(),
                            ));
                        }
                        StreamTargetWire::GuestLoopbackTcp { port }
                    }
                    other => {
                        return Err(ProtocolError::InvalidPayload(format!(
                            "invalid StreamTargetWire tag byte: {other}"
                        )));
                    }
                };
                Self::ConnectStart { target }
            }
            FrameKind::ConnectAck => Self::ConnectAck,
            FrameKind::ConnectError => Self::ConnectError {
                message: reader.read_str()?,
            },
            FrameKind::StreamClose => Self::StreamClose,
            FrameKind::ConfigureNetwork => {
                let enable_egress_proxy =
                    reader.read_bool("ConfigureNetwork.enable_egress_proxy")?;
                let proxy_port = reader.read_u16()?;
                if enable_egress_proxy && proxy_port == 0 {
                    return Err(ProtocolError::InvalidPayload(
                        "ConfigureNetwork proxy_port must be nonzero when egress proxy is enabled"
                            .to_owned(),
                    ));
                }
                Self::ConfigureNetwork {
                    enable_egress_proxy,
                    proxy_port,
                }
            }
            FrameKind::ConfigureNetworkAck => Self::ConfigureNetworkAck {
                proxy_port: reader.read_u16()?,
            },
            FrameKind::EgressOpen => Self::EgressOpen,
        };
        reader.finish(kind)?;
        Ok(msg)
    }
}

#[allow(clippy::too_many_arguments)]
fn encode_exec_start(
    target: &ExecTargetWire,
    argv: &[String],
    env: &BTreeMap<String, String>,
    cwd: Option<&str>,
    user: Option<&str>,
    deadline_ms: u64,
    stdout_budget_bytes: u64,
    stderr_budget_bytes: u64,
) -> Result<Vec<u8>, ProtocolError> {
    if argv.is_empty() {
        return Err(ProtocolError::InvalidPayload(
            "ExecStart argv must not be empty".to_owned(),
        ));
    }
    let argc = u32::try_from(argv.len()).map_err(|_| ProtocolError::PayloadTooLarge {
        len: u32::MAX,
        max: MAX_FRAME_PAYLOAD_BYTES,
    })?;
    let envc = u32::try_from(env.len()).map_err(|_| ProtocolError::PayloadTooLarge {
        len: u32::MAX,
        max: MAX_FRAME_PAYLOAD_BYTES,
    })?;

    let mut writer = PayloadWriter::new();
    match target {
        ExecTargetWire::Guest => writer.write_u8(0)?,
        ExecTargetWire::Container { id_or_name } => {
            writer.write_u8(1)?;
            writer.write_str(id_or_name)?;
        }
    }
    writer.write_u32(argc)?;
    for arg in argv {
        writer.write_str(arg)?;
    }
    writer.write_u32(envc)?;
    for (key, value) in env {
        writer.write_str(key)?;
        writer.write_str(value)?;
    }
    writer.write_opt_str(cwd)?;
    writer.write_opt_str(user)?;
    writer.write_u64(deadline_ms)?;
    writer.write_u64(stdout_budget_bytes)?;
    writer.write_u64(stderr_budget_bytes)?;
    Ok(writer.finish())
}

fn decode_exec_start(reader: &mut PayloadReader<'_>) -> Result<Message, ProtocolError> {
    let target = match reader.read_u8()? {
        0 => ExecTargetWire::Guest,
        1 => ExecTargetWire::Container {
            id_or_name: reader.read_str()?,
        },
        other => {
            return Err(ProtocolError::InvalidPayload(format!(
                "invalid ExecTargetWire tag byte: {other}"
            )));
        }
    };

    let argc = reader.read_u32()? as usize;
    if argc == 0 {
        return Err(ProtocolError::InvalidPayload(
            "ExecStart argv must not be empty".to_owned(),
        ));
    }
    // Bound preallocation by remaining bytes (each entry requires at least a 4-byte length prefix).
    if argc > reader.remaining() / 4 {
        return Err(ProtocolError::InvalidPayload(format!(
            "ExecStart argc {argc} exceeds remaining payload bytes ({})",
            reader.remaining()
        )));
    }
    let mut argv = Vec::with_capacity(argc);
    for _ in 0..argc {
        argv.push(reader.read_str()?);
    }

    let envc = reader.read_u32()? as usize;
    // Each env pair requires at least two 4-byte length prefixes.
    if envc > reader.remaining() / 8 {
        return Err(ProtocolError::InvalidPayload(format!(
            "ExecStart envc {envc} exceeds remaining payload bytes ({})",
            reader.remaining()
        )));
    }
    let mut env = BTreeMap::new();
    for _ in 0..envc {
        let key = reader.read_str()?;
        let value = reader.read_str()?;
        if env.insert(key, value).is_some() {
            return Err(ProtocolError::InvalidPayload(
                "ExecStart env contains duplicate key".to_owned(),
            ));
        }
    }

    let cwd = reader.read_opt_str("ExecStart.cwd")?;
    let user = reader.read_opt_str("ExecStart.user")?;
    let deadline_ms = reader.read_u64()?;
    let stdout_budget_bytes = reader.read_u64()?;
    let stderr_budget_bytes = reader.read_u64()?;

    Ok(Message::ExecStart {
        target,
        argv,
        env,
        cwd,
        user,
        deadline_ms,
        stdout_budget_bytes,
        stderr_budget_bytes,
    })
}

struct PayloadWriter {
    buf: Vec<u8>,
}

impl PayloadWriter {
    fn new() -> Self {
        Self { buf: Vec::new() }
    }

    fn with_capacity(cap: usize) -> Result<Self, ProtocolError> {
        check_payload_len(cap)?;
        Ok(Self {
            buf: Vec::with_capacity(cap),
        })
    }

    fn reserve_extra(&self, extra: usize) -> Result<(), ProtocolError> {
        let next = self
            .buf
            .len()
            .checked_add(extra)
            .ok_or(ProtocolError::PayloadTooLarge {
                len: u32::MAX,
                max: MAX_FRAME_PAYLOAD_BYTES,
            })?;
        check_payload_len(next)?;
        Ok(())
    }

    fn write_u8(&mut self, value: u8) -> Result<(), ProtocolError> {
        self.reserve_extra(1)?;
        self.buf.push(value);
        Ok(())
    }

    fn write_bool(&mut self, value: bool) -> Result<(), ProtocolError> {
        self.write_u8(u8::from(value))
    }

    fn write_bytes(&mut self, bytes: &[u8]) -> Result<(), ProtocolError> {
        self.reserve_extra(bytes.len())?;
        self.buf.extend_from_slice(bytes);
        Ok(())
    }

    fn write_u16(&mut self, value: u16) -> Result<(), ProtocolError> {
        self.write_bytes(&value.to_be_bytes())
    }

    fn write_u32(&mut self, value: u32) -> Result<(), ProtocolError> {
        self.write_bytes(&value.to_be_bytes())
    }

    fn write_i32(&mut self, value: i32) -> Result<(), ProtocolError> {
        self.write_bytes(&value.to_be_bytes())
    }

    fn write_u64(&mut self, value: u64) -> Result<(), ProtocolError> {
        self.write_bytes(&value.to_be_bytes())
    }

    fn write_str(&mut self, s: &str) -> Result<(), ProtocolError> {
        let len = u32::try_from(s.len()).map_err(|_| ProtocolError::PayloadTooLarge {
            len: u32::MAX,
            max: MAX_FRAME_PAYLOAD_BYTES,
        })?;
        let extra = 4usize
            .checked_add(s.len())
            .ok_or(ProtocolError::PayloadTooLarge {
                len: u32::MAX,
                max: MAX_FRAME_PAYLOAD_BYTES,
            })?;
        self.reserve_extra(extra)?;
        self.buf.extend_from_slice(&len.to_be_bytes());
        self.buf.extend_from_slice(s.as_bytes());
        Ok(())
    }

    fn write_opt_str(&mut self, opt: Option<&str>) -> Result<(), ProtocolError> {
        match opt {
            None => self.write_u8(0),
            Some(s) => {
                self.write_u8(1)?;
                self.write_str(s)
            }
        }
    }

    fn write_opt_i32(&mut self, opt: Option<i32>) -> Result<(), ProtocolError> {
        match opt {
            None => self.write_u8(0),
            Some(v) => {
                self.write_u8(1)?;
                self.write_i32(v)
            }
        }
    }

    fn finish(self) -> Vec<u8> {
        self.buf
    }
}

struct PayloadReader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> PayloadReader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    fn read_bytes(&mut self, len: usize) -> Result<&'a [u8], ProtocolError> {
        let end = self.pos.checked_add(len).ok_or_else(|| {
            ProtocolError::InvalidPayload("payload length arithmetic overflow".to_owned())
        })?;
        let slice = self.buf.get(self.pos..end).ok_or_else(|| {
            ProtocolError::InvalidPayload(format!(
                "truncated payload: needed {len} bytes, only {} remaining",
                self.remaining()
            ))
        })?;
        self.pos = end;
        Ok(slice)
    }

    fn read_array<const N: usize>(&mut self) -> Result<[u8; N], ProtocolError> {
        let slice = self.read_bytes(N)?;
        let mut arr = [0u8; N];
        arr.copy_from_slice(slice);
        Ok(arr)
    }

    fn read_u8(&mut self) -> Result<u8, ProtocolError> {
        Ok(self.read_bytes(1)?[0])
    }

    fn read_bool(&mut self, field: &str) -> Result<bool, ProtocolError> {
        match self.read_u8()? {
            0 => Ok(false),
            1 => Ok(true),
            other => Err(ProtocolError::InvalidPayload(format!(
                "invalid boolean byte for {field}: {other}"
            ))),
        }
    }

    fn read_u16(&mut self) -> Result<u16, ProtocolError> {
        Ok(u16::from_be_bytes(self.read_array()?))
    }

    fn read_u32(&mut self) -> Result<u32, ProtocolError> {
        Ok(u32::from_be_bytes(self.read_array()?))
    }

    fn read_i32(&mut self) -> Result<i32, ProtocolError> {
        Ok(i32::from_be_bytes(self.read_array()?))
    }

    fn read_u64(&mut self) -> Result<u64, ProtocolError> {
        Ok(u64::from_be_bytes(self.read_array()?))
    }

    fn read_str(&mut self) -> Result<String, ProtocolError> {
        let len = self.read_u32()? as usize;
        let raw = self.read_bytes(len)?;
        Ok(std::str::from_utf8(raw)?.to_owned())
    }

    fn read_opt_str(&mut self, field: &str) -> Result<Option<String>, ProtocolError> {
        match self.read_u8()? {
            0 => Ok(None),
            1 => Ok(Some(self.read_str()?)),
            other => Err(ProtocolError::InvalidPayload(format!(
                "invalid option tag byte for {field}: {other}"
            ))),
        }
    }

    fn read_opt_i32(&mut self, field: &str) -> Result<Option<i32>, ProtocolError> {
        match self.read_u8()? {
            0 => Ok(None),
            1 => Ok(Some(self.read_i32()?)),
            other => Err(ProtocolError::InvalidPayload(format!(
                "invalid option tag byte for {field}: {other}"
            ))),
        }
    }

    fn take_rest(&mut self) -> &'a [u8] {
        let rest = &self.buf[self.pos..];
        self.pos = self.buf.len();
        rest
    }

    fn finish(self, kind: FrameKind) -> Result<(), ProtocolError> {
        if self.pos != self.buf.len() {
            return Err(ProtocolError::InvalidPayload(format!(
                "trailing {} byte(s) in {kind:?} payload",
                self.remaining()
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PROTOCOL_VERSION;

    fn sample_guest_exec_start() -> Message {
        Message::ExecStart {
            target: ExecTargetWire::Guest,
            argv: vec![
                "/bin/sh".to_owned(),
                "-c".to_owned(),
                "".to_owned(),
                "echo xin chào".to_owned(),
            ],
            env: BTreeMap::new(),
            cwd: None,
            user: None,
            deadline_ms: 15_000,
            stdout_budget_bytes: 1_048_576,
            stderr_budget_bytes: 262_144,
        }
    }

    #[test]
    fn all_message_variants_roundtrip() {
        let mut populated_env = BTreeMap::new();
        populated_env.insert("Z_VAR".to_owned(), "last".to_owned());
        populated_env.insert("A_VAR".to_owned(), "first".to_owned());
        populated_env.insert("EMPTY".to_owned(), String::new());

        let samples = vec![
            (Message::Hello { version: PROTOCOL_VERSION }, Lane::Control),
            (
                Message::HelloAck {
                    version: PROTOCOL_VERSION,
                    features: 0xA55A_0001,
                },
                Lane::Control,
            ),
            (sample_guest_exec_start(), Lane::Control),
            (
                Message::ExecStart {
                    target: ExecTargetWire::Container {
                        id_or_name: "pg-test-123".to_owned(),
                    },
                    argv: vec!["psql".to_owned(), "-U".to_owned(), "app".to_owned()],
                    env: populated_env,
                    cwd: Some("/workspace/db".to_owned()),
                    user: Some("1000:1000".to_owned()),
                    deadline_ms: u64::MAX,
                    stdout_budget_bytes: 0,
                    stderr_budget_bytes: u64::MAX,
                },
                Lane::Control,
            ),
            (
                Message::StreamData {
                    channel: StreamChannel::Stdin,
                    eof: false,
                    data: b"hello\n".to_vec(),
                },
                Lane::Data,
            ),
            (
                Message::StreamData {
                    channel: StreamChannel::Stdout,
                    eof: true,
                    data: Vec::new(),
                },
                Lane::Data,
            ),
            (
                Message::StreamData {
                    channel: StreamChannel::Stderr,
                    eof: false,
                    data: vec![0, 255, 128],
                },
                Lane::Data,
            ),
            (
                Message::StreamCredit {
                    channel: StreamChannel::Stdout,
                    bytes: 65_536,
                },
                Lane::Control,
            ),
            (Message::ExecCancel, Lane::Control),
            (
                Message::ExecExit {
                    code: Some(0),
                    timed_out: false,
                    stdout_truncated: false,
                    stderr_truncated: false,
                },
                Lane::Control,
            ),
            (
                Message::ExecExit {
                    code: Some(-1),
                    timed_out: false,
                    stdout_truncated: true,
                    stderr_truncated: false,
                },
                Lane::Control,
            ),
            (
                Message::ExecExit {
                    code: None,
                    timed_out: true,
                    stdout_truncated: true,
                    stderr_truncated: true,
                },
                Lane::Control,
            ),
            (Message::Ping { seq: u64::MAX }, Lane::Control),
            (Message::Pong { seq: 42 }, Lane::Control),
            (Message::Shutdown, Lane::Control),
            (
                Message::CopyInStart {
                    dst_guest: "/workspace/src".to_owned(),
                    max_bytes: 8 * 1024 * 1024,
                },
                Lane::Control,
            ),
            (
                Message::CopyOutStart {
                    src_guest: "/workspace/dist".to_owned(),
                    max_bytes: 16 * 1024 * 1024,
                },
                Lane::Control,
            ),
            (
                Message::CopyDone {
                    bytes_transferred: 123_456,
                },
                Lane::Data,
            ),
            (
                Message::CopyError {
                    message: "tar entry escapes root".to_owned(),
                },
                Lane::Control,
            ),
            (
                Message::ConnectStart {
                    target: StreamTargetWire::PodmanUnixSocket,
                },
                Lane::Control,
            ),
            (
                Message::ConnectStart {
                    target: StreamTargetWire::GuestLoopbackTcp { port: 1 },
                },
                Lane::Control,
            ),
            (
                Message::ConnectStart {
                    target: StreamTargetWire::GuestLoopbackTcp { port: 5432 },
                },
                Lane::Control,
            ),
            (
                Message::ConnectStart {
                    target: StreamTargetWire::GuestLoopbackTcp { port: u16::MAX },
                },
                Lane::Control,
            ),
            (Message::ConnectAck, Lane::Control),
            (
                Message::ConnectError {
                    message: "connection refused".to_owned(),
                },
                Lane::Control,
            ),
            (Message::StreamClose, Lane::Control),
            (
                Message::ConfigureNetwork {
                    enable_egress_proxy: false,
                    proxy_port: 0,
                },
                Lane::Control,
            ),
            (
                Message::ConfigureNetwork {
                    enable_egress_proxy: true,
                    proxy_port: 3128,
                },
                Lane::Control,
            ),
            (
                Message::ConfigureNetworkAck { proxy_port: 0 },
                Lane::Control,
            ),
            (
                Message::ConfigureNetworkAck { proxy_port: 3128 },
                Lane::Control,
            ),
            (Message::EgressOpen, Lane::Control),
        ];

        for (msg, expected_lane) in samples {
            assert_eq!(msg.lane(), expected_lane);
            let payload = msg.encode_payload().expect("valid message encodes");
            let decoded =
                Message::decode(msg.kind(), &payload).expect("valid payload decodes");
            assert_eq!(decoded, msg);
        }
    }

    #[test]
    fn exec_start_env_encoding_is_deterministic() {
        let mut env_a = BTreeMap::new();
        env_a.insert("B".to_owned(), "2".to_owned());
        env_a.insert("A".to_owned(), "1".to_owned());
        env_a.insert("C".to_owned(), "3".to_owned());

        let mut env_b = BTreeMap::new();
        env_b.insert("C".to_owned(), "3".to_owned());
        env_b.insert("A".to_owned(), "1".to_owned());
        env_b.insert("B".to_owned(), "2".to_owned());

        let msg_a = Message::ExecStart {
            target: ExecTargetWire::Guest,
            argv: vec!["env".to_owned()],
            env: env_a,
            cwd: None,
            user: None,
            deadline_ms: 1000,
            stdout_budget_bytes: 1024,
            stderr_budget_bytes: 1024,
        };
        let msg_b = Message::ExecStart {
            target: ExecTargetWire::Guest,
            argv: vec!["env".to_owned()],
            env: env_b,
            cwd: None,
            user: None,
            deadline_ms: 1000,
            stdout_budget_bytes: 1024,
            stderr_budget_bytes: 1024,
        };

        assert_eq!(msg_a.encode_payload().unwrap(), msg_b.encode_payload().unwrap());
    }

    #[test]
    fn stream_channel_rejects_invalid_discriminant() {
        assert_eq!(StreamChannel::try_from(0), Ok(StreamChannel::Stdin));
        assert_eq!(StreamChannel::try_from(1), Ok(StreamChannel::Stdout));
        assert_eq!(StreamChannel::try_from(2), Ok(StreamChannel::Stderr));
        assert!(matches!(
            StreamChannel::try_from(3),
            Err(ProtocolError::InvalidPayload(_))
        ));
        assert!(matches!(
            Message::decode(FrameKind::StreamData, &[9, 0, 1, 2]),
            Err(ProtocolError::InvalidPayload(_))
        ));
        assert!(matches!(
            Message::decode(FrameKind::StreamCredit, &[9, 0, 0, 0, 16]),
            Err(ProtocolError::InvalidPayload(_))
        ));
    }

    #[test]
    fn decode_rejects_invalid_eof_flag() {
        assert!(matches!(
            Message::decode(FrameKind::StreamData, &[1, 2, b'a']),
            Err(ProtocolError::InvalidPayload(_))
        ));
    }

    #[test]
    fn exec_start_rejects_empty_argv_invalid_tags_duplicate_env_and_invalid_utf8() {
        let empty = Message::ExecStart {
            target: ExecTargetWire::Guest,
            argv: Vec::new(),
            env: BTreeMap::new(),
            cwd: None,
            user: None,
            deadline_ms: 1000,
            stdout_budget_bytes: 1024,
            stderr_budget_bytes: 1024,
        };
        assert!(matches!(
            empty.encode_payload(),
            Err(ProtocolError::InvalidPayload(_))
        ));

        // target=Guest (0), argc=0.
        let mut zero_argc = vec![0u8];
        zero_argc.extend_from_slice(&0u32.to_be_bytes());
        assert!(matches!(
            Message::decode(FrameKind::ExecStart, &zero_argc),
            Err(ProtocolError::InvalidPayload(_))
        ));

        // target=Guest (0), argc=u32::MAX (must fail preallocation bound without OOM).
        let mut huge_argc = vec![0u8];
        huge_argc.extend_from_slice(&u32::MAX.to_be_bytes());
        assert!(matches!(
            Message::decode(FrameKind::ExecStart, &huge_argc),
            Err(ProtocolError::InvalidPayload(_))
        ));

        // Invalid ExecTargetWire discriminant (2).
        let mut bad_target = sample_guest_exec_start().encode_payload().unwrap();
        bad_target[0] = 2;
        assert!(matches!(
            Message::decode(FrameKind::ExecStart, &bad_target),
            Err(ProtocolError::InvalidPayload(_))
        ));

        // Invalid UTF-8 in argv[0] (target=Guest, argc=1, len=2, [0xFF, 0xFE]).
        let mut bad_utf8 = vec![0u8];
        bad_utf8.extend_from_slice(&1u32.to_be_bytes());
        bad_utf8.extend_from_slice(&2u32.to_be_bytes());
        bad_utf8.extend_from_slice(&[0xFF, 0xFE]);
        assert_eq!(
            Message::decode(FrameKind::ExecStart, &bad_utf8),
            Err(ProtocolError::InvalidUtf8)
        );

        // Invalid UTF-8 in ExecTargetWire::Container id_or_name.
        let mut bad_container_utf8 = vec![1u8];
        bad_container_utf8.extend_from_slice(&2u32.to_be_bytes());
        bad_container_utf8.extend_from_slice(&[0xFF, 0xFE]);
        assert_eq!(
            Message::decode(FrameKind::ExecStart, &bad_container_utf8),
            Err(ProtocolError::InvalidUtf8)
        );

        // Duplicate env key: target=Guest, argc=1 ("a"), envc=2 ("K"="1", "K"="2"), cwd=None, user=None, 3x u64=0.
        let mut dup_env = Vec::new();
        dup_env.push(0u8);
        dup_env.extend_from_slice(&1u32.to_be_bytes());
        dup_env.extend_from_slice(&1u32.to_be_bytes());
        dup_env.push(b'a');
        dup_env.extend_from_slice(&2u32.to_be_bytes());
        for val in *b"12" {
            dup_env.extend_from_slice(&1u32.to_be_bytes());
            dup_env.push(b'K');
            dup_env.extend_from_slice(&1u32.to_be_bytes());
            dup_env.push(val);
        }
        dup_env.extend_from_slice(&[0u8, 0u8]);
        dup_env.extend_from_slice(&[0u8; 24]);
        assert!(matches!(
            Message::decode(FrameKind::ExecStart, &dup_env),
            Err(ProtocolError::InvalidPayload(_))
        ));

        // Huge envc exceeding remaining payload bytes.
        let mut huge_envc = vec![0u8];
        huge_envc.extend_from_slice(&1u32.to_be_bytes());
        huge_envc.extend_from_slice(&1u32.to_be_bytes());
        huge_envc.push(b'a');
        huge_envc.extend_from_slice(&u32::MAX.to_be_bytes());
        assert!(matches!(
            Message::decode(FrameKind::ExecStart, &huge_envc),
            Err(ProtocolError::InvalidPayload(_))
        ));

        // Invalid Option tag on cwd (offset: 1(target) + 4(argc) + 5("a") + 4(envc=0) = 14).
        let mut base = Vec::new();
        base.push(0u8);
        base.extend_from_slice(&1u32.to_be_bytes());
        base.extend_from_slice(&1u32.to_be_bytes());
        base.push(b'a');
        base.extend_from_slice(&0u32.to_be_bytes());
        base.push(2u8); // invalid cwd tag
        base.push(0u8);
        base.extend_from_slice(&[0u8; 24]);
        assert!(matches!(
            Message::decode(FrameKind::ExecStart, &base),
            Err(ProtocolError::InvalidPayload(_))
        ));

        // Invalid Option tag on user.
        base[14] = 0; // valid cwd=None
        base[15] = 2; // invalid user tag
        assert!(matches!(
            Message::decode(FrameKind::ExecStart, &base),
            Err(ProtocolError::InvalidPayload(_))
        ));
    }

    #[test]
    fn exec_exit_and_copy_reject_invalid_discriminants_and_utf8() {
        // Invalid code tag byte (2).
        assert!(matches!(
            Message::decode(FrameKind::ExecExit, &[2, 0, 0, 0]),
            Err(ProtocolError::InvalidPayload(_))
        ));
        // Invalid timed_out / stdout_truncated / stderr_truncated bool bytes.
        assert!(matches!(
            Message::decode(FrameKind::ExecExit, &[0, 2, 0, 0]),
            Err(ProtocolError::InvalidPayload(_))
        ));
        assert!(matches!(
            Message::decode(FrameKind::ExecExit, &[0, 0, 2, 0]),
            Err(ProtocolError::InvalidPayload(_))
        ));
        assert!(matches!(
            Message::decode(FrameKind::ExecExit, &[0, 0, 0, 2]),
            Err(ProtocolError::InvalidPayload(_))
        ));

        // Invalid UTF-8 in CopyInStart, CopyOutStart, CopyError.
        let mut bad_copy_start = Vec::new();
        bad_copy_start.extend_from_slice(&2u32.to_be_bytes());
        bad_copy_start.extend_from_slice(&[0xFF, 0xFE]);
        bad_copy_start.extend_from_slice(&1024u64.to_be_bytes());
        assert_eq!(
            Message::decode(FrameKind::CopyInStart, &bad_copy_start),
            Err(ProtocolError::InvalidUtf8)
        );
        assert_eq!(
            Message::decode(FrameKind::CopyOutStart, &bad_copy_start),
            Err(ProtocolError::InvalidUtf8)
        );

        let mut bad_copy_err = Vec::new();
        bad_copy_err.extend_from_slice(&2u32.to_be_bytes());
        bad_copy_err.extend_from_slice(&[0xFF, 0xFE]);
        assert_eq!(
            Message::decode(FrameKind::CopyError, &bad_copy_err),
            Err(ProtocolError::InvalidUtf8)
        );
    }

    #[test]
    fn decode_rejects_truncated_and_trailing_payloads() {
        let mut rich_env = BTreeMap::new();
        rich_env.insert("K".to_owned(), "V".to_owned());
        let rich_exec = Message::ExecStart {
            target: ExecTargetWire::Container {
                id_or_name: "box1".to_owned(),
            },
            argv: vec!["/bin/sh".to_owned()],
            env: rich_env,
            cwd: Some("/work".to_owned()),
            user: Some("root".to_owned()),
            deadline_ms: 500,
            stdout_budget_bytes: 100,
            stderr_budget_bytes: 100,
        };
        let exit_some = Message::ExecExit {
            code: Some(42),
            timed_out: false,
            stdout_truncated: true,
            stderr_truncated: false,
        };
        let exit_none = Message::ExecExit {
            code: None,
            timed_out: true,
            stdout_truncated: false,
            stderr_truncated: false,
        };
        let copy_in = Message::CopyInStart {
            dst_guest: "/work".to_owned(),
            max_bytes: 1024,
        };
        let copy_out = Message::CopyOutStart {
            src_guest: "/work".to_owned(),
            max_bytes: 2048,
        };
        let copy_done = Message::CopyDone {
            bytes_transferred: 99,
        };
        let copy_error = Message::CopyError {
            message: "denied".to_owned(),
        };
        let connect_unix = Message::ConnectStart {
            target: StreamTargetWire::PodmanUnixSocket,
        };
        let connect_tcp = Message::ConnectStart {
            target: StreamTargetWire::GuestLoopbackTcp { port: 8080 },
        };
        let connect_error = Message::ConnectError {
            message: "dial failed".to_owned(),
        };
        let cfg_net_enabled = Message::ConfigureNetwork {
            enable_egress_proxy: true,
            proxy_port: 3128,
        };
        let cfg_net_disabled = Message::ConfigureNetwork {
            enable_egress_proxy: false,
            proxy_port: 0,
        };
        let cfg_net_ack = Message::ConfigureNetworkAck { proxy_port: 3128 };

        // Every proper prefix of every structured message must fail with InvalidPayload.
        for msg in [
            rich_exec,
            exit_some,
            exit_none,
            copy_in,
            copy_out,
            copy_done,
            copy_error,
            connect_unix,
            connect_tcp,
            connect_error,
            cfg_net_enabled,
            cfg_net_disabled,
            cfg_net_ack,
        ] {
            let valid = msg.encode_payload().unwrap();
            for prefix_len in 0..valid.len() {
                assert!(
                    matches!(
                        Message::decode(msg.kind(), &valid[..prefix_len]),
                        Err(ProtocolError::InvalidPayload(_))
                    ),
                    "expected InvalidPayload for {:?} truncated at {prefix_len}/{}",
                    msg.kind(),
                    valid.len()
                );
            }
            let mut with_trailing = valid;
            with_trailing.push(0xAA);
            assert!(
                matches!(
                    Message::decode(msg.kind(), &with_trailing),
                    Err(ProtocolError::InvalidPayload(_))
                ),
                "expected InvalidPayload for trailing byte in {:?}",
                msg.kind()
            );
        }

        let static_truncated_cases = [
            (FrameKind::Hello, vec![]),
            (FrameKind::HelloAck, vec![1, 0, 0, 0]),
            (FrameKind::StreamData, vec![0]),
            (FrameKind::StreamCredit, vec![0, 0, 0, 1]),
            (FrameKind::Ping, vec![1, 2, 3, 4, 5, 6, 7]),
            (FrameKind::Pong, vec![1, 2, 3]),
        ];
        for (kind, payload) in static_truncated_cases {
            assert!(
                matches!(Message::decode(kind, &payload), Err(ProtocolError::InvalidPayload(_))),
                "expected InvalidPayload for truncated {kind:?}"
            );
        }

        let static_trailing_cases = [
            (FrameKind::Hello, vec![1, 99]),
            (FrameKind::HelloAck, vec![1, 0, 0, 0, 0, 99]),
            (FrameKind::StreamCredit, vec![1, 0, 0, 0, 8, 0]),
            (FrameKind::ExecCancel, vec![0]),
            (FrameKind::Ping, vec![0; 9]),
            (FrameKind::Pong, vec![0; 9]),
            (FrameKind::Shutdown, vec![1]),
            (FrameKind::ConnectAck, vec![0]),
            (FrameKind::StreamClose, vec![0]),
            (FrameKind::EgressOpen, vec![0]),
        ];
        for (kind, payload) in static_trailing_cases {
            assert!(
                matches!(Message::decode(kind, &payload), Err(ProtocolError::InvalidPayload(_))),
                "expected InvalidPayload for trailing bytes in {kind:?}"
            );
        }
    }

    #[test]
    fn oversized_message_payload_is_rejected() {
        let too_big_stream = Message::StreamData {
            channel: StreamChannel::Stdout,
            eof: false,
            data: vec![0u8; MAX_FRAME_PAYLOAD_BYTES as usize - 1],
        };
        assert!(matches!(
            too_big_stream.encode_payload(),
            Err(ProtocolError::PayloadTooLarge { .. })
        ));

        let too_big_exec = Message::ExecStart {
            target: ExecTargetWire::Guest,
            argv: vec!["x".repeat(MAX_FRAME_PAYLOAD_BYTES as usize)],
            env: BTreeMap::new(),
            cwd: None,
            user: None,
            deadline_ms: 1,
            stdout_budget_bytes: 1,
            stderr_budget_bytes: 1,
        };
        assert!(matches!(
            too_big_exec.encode_payload(),
            Err(ProtocolError::PayloadTooLarge { .. })
        ));

        let too_big_copy_in = Message::CopyInStart {
            dst_guest: "a".repeat(MAX_FRAME_PAYLOAD_BYTES as usize),
            max_bytes: 10,
        };
        assert!(matches!(
            too_big_copy_in.encode_payload(),
            Err(ProtocolError::PayloadTooLarge { .. })
        ));

        let too_big_copy_err = Message::CopyError {
            message: "e".repeat(MAX_FRAME_PAYLOAD_BYTES as usize - 3),
        };
        assert!(matches!(
            too_big_copy_err.encode_payload(),
            Err(ProtocolError::PayloadTooLarge { .. })
        ));

        let too_big_connect_err = Message::ConnectError {
            message: "e".repeat(MAX_FRAME_PAYLOAD_BYTES as usize - 3),
        };
        assert!(matches!(
            too_big_connect_err.encode_payload(),
            Err(ProtocolError::PayloadTooLarge { .. })
        ));
    }

    #[test]
    fn connect_start_rejects_port_zero_and_invalid_targets_and_connect_error_utf8() {
        let zero_port = Message::ConnectStart {
            target: StreamTargetWire::GuestLoopbackTcp { port: 0 },
        };
        assert!(matches!(
            zero_port.encode_payload(),
            Err(ProtocolError::InvalidPayload(_))
        ));

        // Raw payload with GuestLoopbackTcp tag (1) and port 0 must be rejected by decode.
        assert!(matches!(
            Message::decode(FrameKind::ConnectStart, &[1, 0, 0]),
            Err(ProtocolError::InvalidPayload(_))
        ));

        // Invalid StreamTargetWire tags.
        for bad_tag in [2u8, 255u8] {
            assert!(matches!(
                Message::decode(FrameKind::ConnectStart, &[bad_tag]),
                Err(ProtocolError::InvalidPayload(_))
            ));
            assert!(matches!(
                Message::decode(FrameKind::ConnectStart, &[bad_tag, 0, 80]),
                Err(ProtocolError::InvalidPayload(_))
            ));
        }

        // Invalid UTF-8 in ConnectError.
        let mut bad_connect_err = Vec::new();
        bad_connect_err.extend_from_slice(&2u32.to_be_bytes());
        bad_connect_err.extend_from_slice(&[0xFF, 0xFE]);
        assert_eq!(
            Message::decode(FrameKind::ConnectError, &bad_connect_err),
            Err(ProtocolError::InvalidUtf8)
        );
    }

    #[test]
    fn configure_network_rejects_port_zero_when_enabled_and_invalid_bool() {
        let zero_enabled = Message::ConfigureNetwork {
            enable_egress_proxy: true,
            proxy_port: 0,
        };
        assert!(matches!(
            zero_enabled.encode_payload(),
            Err(ProtocolError::InvalidPayload(_))
        ));
        assert!(matches!(
            Message::decode(FrameKind::ConfigureNetwork, &[1, 0, 0]),
            Err(ProtocolError::InvalidPayload(_))
        ));
        assert!(matches!(
            Message::decode(FrameKind::ConfigureNetwork, &[2, 0x0c, 0x38]),
            Err(ProtocolError::InvalidPayload(_))
        ));
        // Disabled proxy allows port 0 cleanly.
        assert_eq!(
            Message::decode(FrameKind::ConfigureNetwork, &[0, 0, 0]).unwrap(),
            Message::ConfigureNetwork {
                enable_egress_proxy: false,
                proxy_port: 0,
            }
        );
    }
}
