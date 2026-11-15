#![forbid(unsafe_code)]
//! Versioned binary framing, prioritized control/data lanes, and credit backpressure primitives
//! shared by the host runtime and guest agent.

pub mod message;
pub mod queue;

pub use message::{Message, StreamChannel};
pub use queue::PriorityFrameQueue;

use std::{fmt, io};

pub const PROTOCOL_VERSION: u8 = 1;
pub const FRAME_HEADER_LEN: usize = 12;
pub const MAX_FRAME_PAYLOAD_BYTES: u32 = 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StreamId(pub u32);

impl fmt::Display for StreamId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Priority lane separating urgent control traffic from bulk stdout/stderr or file streams.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Lane {
    Control = 0,
    Data = 1,
}

impl TryFrom<u8> for Lane {
    type Error = ProtocolError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Control),
            1 => Ok(Self::Data),
            other => Err(ProtocolError::InvalidLane(other)),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum FrameKind {
    Hello = 1,
    HelloAck = 2,
    ExecStart = 3,
    StreamData = 4,
    StreamCredit = 5,
    ExecCancel = 6,
    ExecExit = 7,
    Ping = 8,
    Pong = 9,
    Shutdown = 10,
}

impl TryFrom<u8> for FrameKind {
    type Error = ProtocolError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Hello),
            2 => Ok(Self::HelloAck),
            3 => Ok(Self::ExecStart),
            4 => Ok(Self::StreamData),
            5 => Ok(Self::StreamCredit),
            6 => Ok(Self::ExecCancel),
            7 => Ok(Self::ExecExit),
            8 => Ok(Self::Ping),
            9 => Ok(Self::Pong),
            10 => Ok(Self::Shutdown),
            other => Err(ProtocolError::InvalidFrameKind(other)),
        }
    }
}

/// Errors produced during binary framing, payload validation, and wire stream I/O.
#[derive(Debug)]
pub enum ProtocolError {
    UnsupportedVersion(u8),
    InvalidLane(u8),
    InvalidFrameKind(u8),
    PayloadTooLarge { len: u32, max: u32 },
    /// Clean EOF reached at a frame boundary before any header byte was read.
    Eof,
    /// Stream ended mid-header or mid-payload before a full frame completed.
    UnexpectedEof,
    InvalidPayload(String),
    InvalidUtf8,
    Io(io::Error),
}

impl PartialEq for ProtocolError {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::UnsupportedVersion(a), Self::UnsupportedVersion(b)) => a == b,
            (Self::InvalidLane(a), Self::InvalidLane(b)) => a == b,
            (Self::InvalidFrameKind(a), Self::InvalidFrameKind(b)) => a == b,
            (
                Self::PayloadTooLarge { len: al, max: am },
                Self::PayloadTooLarge { len: bl, max: bm },
            ) => al == bl && am == bm,
            (Self::Eof, Self::Eof) => true,
            (Self::UnexpectedEof, Self::UnexpectedEof) => true,
            (Self::InvalidPayload(a), Self::InvalidPayload(b)) => a == b,
            (Self::InvalidUtf8, Self::InvalidUtf8) => true,
            (Self::Io(a), Self::Io(b)) => a.kind() == b.kind() && a.to_string() == b.to_string(),
            _ => false,
        }
    }
}

impl Eq for ProtocolError {}

impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedVersion(v) => {
                write!(f, "unsupported protocol version {v} (expected {PROTOCOL_VERSION})")
            }
            Self::InvalidLane(l) => write!(f, "invalid protocol lane byte: {l}"),
            Self::InvalidFrameKind(k) => write!(f, "invalid protocol frame kind byte: {k}"),
            Self::PayloadTooLarge { len, max } => {
                write!(f, "frame payload length {len} exceeds maximum {max} bytes")
            }
            Self::Eof => write!(f, "clean end of protocol stream"),
            Self::UnexpectedEof => write!(f, "unexpected end of protocol stream mid-frame"),
            Self::InvalidPayload(msg) => write!(f, "invalid frame payload: {msg}"),
            Self::InvalidUtf8 => write!(f, "invalid UTF-8 sequence in frame payload"),
            Self::Io(err) => write!(f, "protocol I/O error: {err}"),
        }
    }
}

impl std::error::Error for ProtocolError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            _ => None,
        }
    }
}

impl From<io::Error> for ProtocolError {
    fn from(err: io::Error) -> Self {
        if err.kind() == io::ErrorKind::UnexpectedEof {
            Self::UnexpectedEof
        } else {
            Self::Io(err)
        }
    }
}

impl From<std::str::Utf8Error> for ProtocolError {
    fn from(_: std::str::Utf8Error) -> Self {
        Self::InvalidUtf8
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrameHeader {
    pub version: u8,
    pub lane: Lane,
    pub kind: FrameKind,
    pub flags: u8,
    pub stream_id: StreamId,
    pub payload_len: u32,
}

impl FrameHeader {
    pub fn new(lane: Lane, kind: FrameKind, stream_id: StreamId, payload_len: u32) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            lane,
            kind,
            flags: 0,
            stream_id,
            payload_len,
        }
    }

    pub fn encode(&self) -> [u8; FRAME_HEADER_LEN] {
        let mut buf = [0u8; FRAME_HEADER_LEN];
        buf[0] = self.version;
        buf[1] = self.lane as u8;
        buf[2] = self.kind as u8;
        buf[3] = self.flags;
        buf[4..8].copy_from_slice(&self.stream_id.0.to_be_bytes());
        buf[8..12].copy_from_slice(&self.payload_len.to_be_bytes());
        buf
    }

    pub fn decode(buf: &[u8; FRAME_HEADER_LEN]) -> Result<Self, ProtocolError> {
        let version = buf[0];
        if version != PROTOCOL_VERSION {
            return Err(ProtocolError::UnsupportedVersion(version));
        }
        let lane = Lane::try_from(buf[1])?;
        let kind = FrameKind::try_from(buf[2])?;
        let flags = buf[3];
        let stream_id = StreamId(u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]));
        let payload_len = u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]);
        if payload_len > MAX_FRAME_PAYLOAD_BYTES {
            return Err(ProtocolError::PayloadTooLarge {
                len: payload_len,
                max: MAX_FRAME_PAYLOAD_BYTES,
            });
        }
        Ok(Self {
            version,
            lane,
            kind,
            flags,
            stream_id,
            payload_len,
        })
    }
}

/// Complete binary protocol frame combining a validated header and raw payload bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Frame {
    pub header: FrameHeader,
    pub payload: Vec<u8>,
}

impl Frame {
    /// Encodes `msg` into a `Frame` addressed to `stream_id` with its canonical lane and kind.
    pub fn from_message(stream_id: StreamId, msg: &Message) -> Result<Self, ProtocolError> {
        let payload = msg.encode_payload()?;
        let payload_len = check_payload_len(payload.len())?;
        let header = FrameHeader::new(msg.lane(), msg.kind(), stream_id, payload_len);
        Ok(Self { header, payload })
    }

    /// Decodes this frame's payload into a typed `Message`, verifying lane and length consistency.
    pub fn decode_message(&self) -> Result<Message, ProtocolError> {
        let expected_len = check_payload_len(self.payload.len())?;
        if self.header.payload_len != expected_len {
            return Err(ProtocolError::InvalidPayload(format!(
                "frame header payload_len {} does not match payload length {expected_len}",
                self.header.payload_len
            )));
        }
        let msg = Message::decode(self.header.kind, &self.payload)?;
        if self.header.lane != msg.lane() {
            return Err(ProtocolError::InvalidLane(self.header.lane as u8));
        }
        Ok(msg)
    }
}

/// Writes `frame` to `writer` and flushes, re-validating header/payload bounds before I/O.
pub fn write_frame<W: io::Write>(writer: &mut W, frame: &Frame) -> Result<(), ProtocolError> {
    let actual_len = check_payload_len(frame.payload.len())?;
    if frame.header.version != PROTOCOL_VERSION {
        return Err(ProtocolError::UnsupportedVersion(frame.header.version));
    }
    if frame.header.payload_len != actual_len {
        return Err(ProtocolError::InvalidPayload(format!(
            "frame header payload_len {} does not match payload length {actual_len}",
            frame.header.payload_len
        )));
    }
    let header_bytes = frame.header.encode();
    writer.write_all(&header_bytes)?;
    if !frame.payload.is_empty() {
        writer.write_all(&frame.payload)?;
    }
    writer.flush()?;
    Ok(())
}

/// Reads one complete frame from `reader`, returning `ProtocolError::Eof` on clean boundary EOF
/// and validating `payload_len` before allocating the payload buffer.
pub fn read_frame<R: io::Read>(reader: &mut R) -> Result<Frame, ProtocolError> {
    let mut header_buf = [0u8; FRAME_HEADER_LEN];
    loop {
        match reader.read(&mut header_buf[..1]) {
            Ok(0) => return Err(ProtocolError::Eof),
            Ok(_) => break,
            Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
            Err(err) => return Err(err.into()),
        }
    }
    reader.read_exact(&mut header_buf[1..])?;

    let header = FrameHeader::decode(&header_buf)?;
    let mut payload = vec![0u8; header.payload_len as usize];
    if !payload.is_empty() {
        reader.read_exact(&mut payload)?;
    }
    Ok(Frame { header, payload })
}

pub(crate) fn check_payload_len(len: usize) -> Result<u32, ProtocolError> {
    if len > MAX_FRAME_PAYLOAD_BYTES as usize {
        return Err(ProtocolError::PayloadTooLarge {
            len: u32::try_from(len).unwrap_or(u32::MAX),
            max: MAX_FRAME_PAYLOAD_BYTES,
        });
    }
    Ok(len as u32)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn frame_header_roundtrip() {
        let header = FrameHeader::new(Lane::Control, FrameKind::ExecCancel, StreamId(42), 128);
        let encoded = header.encode();
        let decoded = FrameHeader::decode(&encoded).expect("valid header should decode");
        assert_eq!(decoded, header);

        let data_header = FrameHeader {
            version: PROTOCOL_VERSION,
            lane: Lane::Data,
            kind: FrameKind::StreamData,
            flags: 1,
            stream_id: StreamId(u32::MAX),
            payload_len: MAX_FRAME_PAYLOAD_BYTES,
        };
        assert_eq!(
            FrameHeader::decode(&data_header.encode()).expect("max valid payload should decode"),
            data_header
        );
    }

    #[test]
    fn decode_rejects_unsupported_version() {
        let mut raw = FrameHeader::new(Lane::Control, FrameKind::Ping, StreamId(0), 0).encode();
        raw[0] = PROTOCOL_VERSION + 1;
        assert_eq!(
            FrameHeader::decode(&raw),
            Err(ProtocolError::UnsupportedVersion(PROTOCOL_VERSION + 1))
        );
    }

    #[test]
    fn decode_rejects_oversized_payload() {
        let mut raw =
            FrameHeader::new(Lane::Data, FrameKind::StreamData, StreamId(7), 0).encode();
        raw[8..12].copy_from_slice(&(MAX_FRAME_PAYLOAD_BYTES + 1).to_be_bytes());
        assert_eq!(
            FrameHeader::decode(&raw),
            Err(ProtocolError::PayloadTooLarge {
                len: MAX_FRAME_PAYLOAD_BYTES + 1,
                max: MAX_FRAME_PAYLOAD_BYTES,
            })
        );
    }

    #[test]
    fn decode_rejects_invalid_lane_or_kind() {
        let mut bad_lane = FrameHeader::new(Lane::Control, FrameKind::Hello, StreamId(0), 0).encode();
        bad_lane[1] = 9;
        assert_eq!(FrameHeader::decode(&bad_lane), Err(ProtocolError::InvalidLane(9)));

        let mut bad_kind = FrameHeader::new(Lane::Control, FrameKind::Hello, StreamId(0), 0).encode();
        bad_kind[2] = 99;
        assert_eq!(
            FrameHeader::decode(&bad_kind),
            Err(ProtocolError::InvalidFrameKind(99))
        );
    }

    #[test]
    fn write_and_read_frame_stream_with_clean_eof() {
        let frames = vec![
            Frame::from_message(StreamId(0), &Message::Hello { version: PROTOCOL_VERSION }).unwrap(),
            Frame::from_message(
                StreamId(7),
                &Message::ExecStart {
                    argv: vec!["/bin/echo".to_owned(), "ok".to_owned()],
                },
            )
            .unwrap(),
            Frame::from_message(
                StreamId(7),
                &Message::StreamData {
                    channel: StreamChannel::Stdout,
                    eof: true,
                    data: b"ok\n".to_vec(),
                },
            )
            .unwrap(),
            Frame::from_message(StreamId(7), &Message::ExecExit { code: 0 }).unwrap(),
        ];

        let mut wire = Vec::new();
        for frame in &frames {
            write_frame(&mut wire, frame).expect("frame should serialize to stream");
        }

        let mut cursor = Cursor::new(wire);
        for expected in &frames {
            let got = read_frame(&mut cursor).expect("frame should read cleanly");
            assert_eq!(&got, expected);
            assert_eq!(
                got.decode_message().expect("message should decode"),
                expected.decode_message().unwrap()
            );
        }
        assert_eq!(read_frame(&mut cursor), Err(ProtocolError::Eof));
    }

    #[test]
    fn read_frame_rejects_truncated_header_and_payload() {
        // Partial header (5 bytes of 12).
        let frame = Frame::from_message(StreamId(1), &Message::Ping { seq: 99 }).unwrap();
        let mut wire = Vec::new();
        write_frame(&mut wire, &frame).unwrap();

        let mut partial_header = Cursor::new(&wire[..5]);
        assert_eq!(read_frame(&mut partial_header), Err(ProtocolError::UnexpectedEof));

        // Full header + only 4 of 8 payload bytes.
        let mut partial_payload = Cursor::new(&wire[..FRAME_HEADER_LEN + 4]);
        assert_eq!(read_frame(&mut partial_payload), Err(ProtocolError::UnexpectedEof));
    }

    #[test]
    fn read_frame_rejects_memory_bomb_header_without_allocating_payload() {
        let mut header = FrameHeader::new(Lane::Data, FrameKind::StreamData, StreamId(1), 0).encode();
        header[8..12].copy_from_slice(&u32::MAX.to_be_bytes());
        let mut cursor = Cursor::new(header);
        assert_eq!(
            read_frame(&mut cursor),
            Err(ProtocolError::PayloadTooLarge {
                len: u32::MAX,
                max: MAX_FRAME_PAYLOAD_BYTES,
            })
        );
    }

    #[test]
    fn write_frame_and_decode_message_enforce_frame_consistency() {
        let mut bad_frame = Frame::from_message(StreamId(1), &Message::Shutdown).unwrap();
        bad_frame.payload = vec![0u8; MAX_FRAME_PAYLOAD_BYTES as usize + 1];
        let mut out = Vec::new();
        assert_eq!(
            write_frame(&mut out, &bad_frame),
            Err(ProtocolError::PayloadTooLarge {
                len: MAX_FRAME_PAYLOAD_BYTES + 1,
                max: MAX_FRAME_PAYLOAD_BYTES,
            })
        );
        assert!(out.is_empty());

        let mut mismatched_len = Frame::from_message(StreamId(1), &Message::Ping { seq: 1 }).unwrap();
        mismatched_len.header.payload_len = 4;
        assert!(matches!(
            write_frame(&mut out, &mismatched_len),
            Err(ProtocolError::InvalidPayload(_))
        ));
        assert!(matches!(
            mismatched_len.decode_message(),
            Err(ProtocolError::InvalidPayload(_))
        ));

        let mut wrong_lane = Frame::from_message(StreamId(1), &Message::ExecCancel).unwrap();
        wrong_lane.header.lane = Lane::Data;
        assert_eq!(wrong_lane.decode_message(), Err(ProtocolError::InvalidLane(Lane::Data as u8)));
    }

    #[test]
    fn read_frame_retries_on_interrupted_first_byte() {
        struct InterruptedOnceReader {
            data: Vec<u8>,
            pos: usize,
            interrupted: bool,
        }

        impl io::Read for InterruptedOnceReader {
            fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                if !self.interrupted {
                    self.interrupted = true;
                    return Err(io::Error::new(io::ErrorKind::Interrupted, "EINTR"));
                }
                let n = buf.len().min(self.data.len() - self.pos);
                buf[..n].copy_from_slice(&self.data[self.pos..self.pos + n]);
                self.pos += n;
                Ok(n)
            }
        }

        let frame = Frame::from_message(StreamId(3), &Message::Pong { seq: 12 }).unwrap();
        let mut wire = Vec::new();
        write_frame(&mut wire, &frame).unwrap();

        let mut reader = InterruptedOnceReader {
            data: wire,
            pos: 0,
            interrupted: false,
        };
        assert_eq!(read_frame(&mut reader).expect("EINTR must be retried"), frame);
    }
}
