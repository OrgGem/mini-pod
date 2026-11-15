#![forbid(unsafe_code)]
//! Versioned binary framing, prioritized control/data lanes, and credit backpressure primitives
//! shared by the host runtime and guest agent.

use std::fmt;

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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProtocolError {
    UnsupportedVersion(u8),
    InvalidLane(u8),
    InvalidFrameKind(u8),
    PayloadTooLarge { len: u32, max: u32 },
}

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
        }
    }
}

impl std::error::Error for ProtocolError {}

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

#[cfg(test)]
mod tests {
    use super::*;

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
}
