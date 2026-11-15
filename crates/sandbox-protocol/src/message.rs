//! Typed protocol messages and strict binary payload codecs.

use crate::{check_payload_len, FrameKind, Lane, ProtocolError, MAX_FRAME_PAYLOAD_BYTES};

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
    /// Starts an execution process inside the sandbox with non-empty `argv`.
    ExecStart { argv: Vec<String> },
    /// Carries raw bytes or EOF for stdin/stdout/stderr on a `StreamId`.
    StreamData {
        channel: StreamChannel,
        eof: bool,
        data: Vec<u8>,
    },
    /// Grants `bytes` of send window credit for flow-controlled stream backpressure.
    StreamCredit { channel: StreamChannel, bytes: u32 },
    /// Requests immediate cancellation of an in-flight execution.
    ExecCancel,
    /// Reports final process exit status after stream termination.
    ExecExit { code: i32 },
    /// Liveness probe carrying caller sequence number.
    Ping { seq: u64 },
    /// Liveness response echoing the `Ping` sequence number.
    Pong { seq: u64 },
    /// Requests graceful guest agent shutdown.
    Shutdown,
}

impl Message {
    /// Returns the priority lane required for this message (`Control` vs `Data`).
    pub fn lane(&self) -> Lane {
        match self {
            Self::StreamData { .. } => Lane::Data,
            Self::Hello { .. }
            | Self::HelloAck { .. }
            | Self::ExecStart { .. }
            | Self::StreamCredit { .. }
            | Self::ExecCancel
            | Self::ExecExit { .. }
            | Self::Ping { .. }
            | Self::Pong { .. }
            | Self::Shutdown => Lane::Control,
        }
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
        }
    }

    /// Encodes this message's payload into big-endian wire bytes within `MAX_FRAME_PAYLOAD_BYTES`.
    pub fn encode_payload(&self) -> Result<Vec<u8>, ProtocolError> {
        match self {
            Self::Hello { version } => Ok(vec![*version]),
            Self::HelloAck { version, features } => {
                let mut buf = Vec::with_capacity(5);
                buf.push(*version);
                buf.extend_from_slice(&features.to_be_bytes());
                Ok(buf)
            }
            Self::ExecStart { argv } => encode_exec_start(argv),
            Self::StreamData { channel, eof, data } => {
                let total = 2usize
                    .checked_add(data.len())
                    .ok_or(ProtocolError::PayloadTooLarge {
                        len: u32::MAX,
                        max: MAX_FRAME_PAYLOAD_BYTES,
                    })?;
                check_payload_len(total)?;
                let mut buf = Vec::with_capacity(total);
                buf.push(*channel as u8);
                buf.push(u8::from(*eof));
                buf.extend_from_slice(data);
                Ok(buf)
            }
            Self::StreamCredit { channel, bytes } => {
                let mut buf = Vec::with_capacity(5);
                buf.push(*channel as u8);
                buf.extend_from_slice(&bytes.to_be_bytes());
                Ok(buf)
            }
            Self::ExecCancel | Self::Shutdown => Ok(Vec::new()),
            Self::ExecExit { code } => Ok(code.to_be_bytes().to_vec()),
            Self::Ping { seq } | Self::Pong { seq } => Ok(seq.to_be_bytes().to_vec()),
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
                let eof = match reader.read_u8()? {
                    0 => false,
                    1 => true,
                    other => {
                        return Err(ProtocolError::InvalidPayload(format!(
                            "invalid eof flag byte in StreamData: {other}"
                        )));
                    }
                };
                let data = reader.take_rest().to_vec();
                return Ok(Self::StreamData { channel, eof, data });
            }
            FrameKind::StreamCredit => Self::StreamCredit {
                channel: StreamChannel::try_from(reader.read_u8()?)?,
                bytes: reader.read_u32()?,
            },
            FrameKind::ExecCancel => Self::ExecCancel,
            FrameKind::ExecExit => Self::ExecExit {
                code: reader.read_i32()?,
            },
            FrameKind::Ping => Self::Ping {
                seq: reader.read_u64()?,
            },
            FrameKind::Pong => Self::Pong {
                seq: reader.read_u64()?,
            },
            FrameKind::Shutdown => Self::Shutdown,
        };
        reader.finish(kind)?;
        Ok(msg)
    }
}

fn encode_exec_start(argv: &[String]) -> Result<Vec<u8>, ProtocolError> {
    if argv.is_empty() {
        return Err(ProtocolError::InvalidPayload(
            "ExecStart argv must not be empty".to_owned(),
        ));
    }
    let mut total = 4usize;
    for arg in argv {
        total = total
            .checked_add(4)
            .and_then(|n| n.checked_add(arg.len()))
            .ok_or(ProtocolError::PayloadTooLarge {
                len: u32::MAX,
                max: MAX_FRAME_PAYLOAD_BYTES,
            })?;
    }
    check_payload_len(total)?;

    let mut buf = Vec::with_capacity(total);
    buf.extend_from_slice(&(argv.len() as u32).to_be_bytes());
    for arg in argv {
        buf.extend_from_slice(&(arg.len() as u32).to_be_bytes());
        buf.extend_from_slice(arg.as_bytes());
    }
    Ok(buf)
}

fn decode_exec_start(reader: &mut PayloadReader<'_>) -> Result<Message, ProtocolError> {
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
        let len = reader.read_u32()? as usize;
        let raw = reader.read_bytes(len)?;
        let arg = std::str::from_utf8(raw)?;
        argv.push(arg.to_owned());
    }
    Ok(Message::ExecStart { argv })
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

    fn read_u8(&mut self) -> Result<u8, ProtocolError> {
        Ok(self.read_bytes(1)?[0])
    }

    fn read_u32(&mut self) -> Result<u32, ProtocolError> {
        let bytes: [u8; 4] = self.read_bytes(4)?.try_into().expect("slice len is 4");
        Ok(u32::from_be_bytes(bytes))
    }

    fn read_i32(&mut self) -> Result<i32, ProtocolError> {
        let bytes: [u8; 4] = self.read_bytes(4)?.try_into().expect("slice len is 4");
        Ok(i32::from_be_bytes(bytes))
    }

    fn read_u64(&mut self) -> Result<u64, ProtocolError> {
        let bytes: [u8; 8] = self.read_bytes(8)?.try_into().expect("slice len is 8");
        Ok(u64::from_be_bytes(bytes))
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

    #[test]
    fn all_message_variants_roundtrip() {
        let samples = vec![
            (Message::Hello { version: PROTOCOL_VERSION }, Lane::Control),
            (
                Message::HelloAck {
                    version: PROTOCOL_VERSION,
                    features: 0xA55A_0001,
                },
                Lane::Control,
            ),
            (
                Message::ExecStart {
                    argv: vec![
                        "/bin/sh".to_owned(),
                        "-c".to_owned(),
                        "".to_owned(),
                        "echo xin chào".to_owned(),
                    ],
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
            (Message::ExecExit { code: -15 }, Lane::Control),
            (Message::Ping { seq: u64::MAX }, Lane::Control),
            (Message::Pong { seq: 42 }, Lane::Control),
            (Message::Shutdown, Lane::Control),
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
    fn exec_start_rejects_empty_argv_and_invalid_utf8() {
        let empty = Message::ExecStart { argv: Vec::new() };
        assert!(matches!(
            empty.encode_payload(),
            Err(ProtocolError::InvalidPayload(_))
        ));
        assert!(matches!(
            Message::decode(FrameKind::ExecStart, &0u32.to_be_bytes()),
            Err(ProtocolError::InvalidPayload(_))
        ));

        // Valid argc=1, len=2, invalid UTF-8 bytes 0xFF 0xFE.
        let mut bad_utf8 = Vec::new();
        bad_utf8.extend_from_slice(&1u32.to_be_bytes());
        bad_utf8.extend_from_slice(&2u32.to_be_bytes());
        bad_utf8.extend_from_slice(&[0xFF, 0xFE]);
        assert_eq!(
            Message::decode(FrameKind::ExecStart, &bad_utf8),
            Err(ProtocolError::InvalidUtf8)
        );
    }

    #[test]
    fn decode_rejects_truncated_and_trailing_payloads() {
        let truncated_cases = [
            (FrameKind::Hello, vec![]),
            (FrameKind::HelloAck, vec![1, 0, 0, 0]),
            (FrameKind::ExecStart, vec![0, 0]),
            (FrameKind::ExecStart, vec![0, 0, 0, 1, 0, 0, 0, 5, b'h', b'i']),
            (FrameKind::ExecStart, u32::MAX.to_be_bytes().to_vec()),
            (FrameKind::StreamData, vec![0]),
            (FrameKind::StreamCredit, vec![0, 0, 0, 1]),
            (FrameKind::ExecExit, vec![0, 0, 0]),
            (FrameKind::Ping, vec![1, 2, 3, 4, 5, 6, 7]),
            (FrameKind::Pong, vec![1, 2, 3]),
        ];
        for (kind, payload) in truncated_cases {
            assert!(
                matches!(Message::decode(kind, &payload), Err(ProtocolError::InvalidPayload(_))),
                "expected InvalidPayload for truncated {kind:?}"
            );
        }

        let trailing_cases = [
            (FrameKind::Hello, vec![1, 99]),
            (FrameKind::HelloAck, vec![1, 0, 0, 0, 0, 99]),
            (
                FrameKind::ExecStart,
                vec![0, 0, 0, 1, 0, 0, 0, 1, b'a', 0xff],
            ),
            (FrameKind::StreamCredit, vec![1, 0, 0, 0, 8, 0]),
            (FrameKind::ExecCancel, vec![0]),
            (FrameKind::ExecExit, vec![0, 0, 0, 0, 1]),
            (FrameKind::Ping, vec![0; 9]),
            (FrameKind::Pong, vec![0; 9]),
            (FrameKind::Shutdown, vec![1]),
        ];
        for (kind, payload) in trailing_cases {
            assert!(
                matches!(Message::decode(kind, &payload), Err(ProtocolError::InvalidPayload(_))),
                "expected InvalidPayload for trailing bytes in {kind:?}"
            );
        }
    }

    #[test]
    fn oversized_message_payload_is_rejected() {
        let too_big = Message::StreamData {
            channel: StreamChannel::Stdout,
            eof: false,
            data: vec![0u8; MAX_FRAME_PAYLOAD_BYTES as usize - 1],
        };
        assert!(matches!(
            too_big.encode_payload(),
            Err(ProtocolError::PayloadTooLarge { .. })
        ));
    }
}
