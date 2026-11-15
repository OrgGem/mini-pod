#![forbid(unsafe_code)]
//! Guest RPC daemon: Phase 1 spike virtio-serial agent loop.
//!
//! Full Execution Supervisor (incremental streaming, process-group / sub-cgroup kill on deadline
//! or stdout/stderr budget overflow) and Podman Unix socket relay are added in Phases 3–4.

use std::fs::OpenOptions;
use std::io::{self, Read, Write};
use std::process::{Command, ExitCode};
use std::thread;
use std::time::{Duration, Instant};

use sandbox_protocol::{
    read_frame, write_frame, Frame, Message, ProtocolError, StreamChannel, StreamId,
    MAX_FRAME_PAYLOAD_BYTES, PROTOCOL_VERSION,
};

const VIRTIO_PORT_CANDIDATES: [&str; 2] =
    ["/dev/virtio-ports/org.minipod.agent.0", "/dev/vport0p1"];
const PORT_OPEN_TIMEOUT: Duration = Duration::from_secs(5);
const PORT_OPEN_POLL_INTERVAL: Duration = Duration::from_millis(50);

/// Maximum raw `StreamData` payload bytes per frame (`MAX_FRAME_PAYLOAD_BYTES` minus 2-byte header).
const MAX_STREAM_DATA_CHUNK_BYTES: usize = MAX_FRAME_PAYLOAD_BYTES as usize - 2;

/// Runs one guest-initiated protocol session over `reader` and `writer`.
///
/// Protocol contract:
/// 1. Guest immediately sends `Hello` on `StreamId(0)` and waits for `HelloAck` on `StreamId(0)`
///    matching [`PROTOCOL_VERSION`].
/// 2. `Ping` replies with `Pong` preserving `stream_id`.
/// 3. `ExecStart` runs the command, streams `Stdout` and `Stderr` as `StreamData` chunks
///    (terminated with `eof: true` on each channel, preserving `stream_id`), and sends `ExecExit`.
/// 4. `Shutdown` replies with `Shutdown` on `StreamId(0)` and returns `Ok(())`.
/// 5. Clean frame-boundary EOF returns `Ok(())`.
pub fn serve_session<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
) -> Result<(), ProtocolError> {
    // Guest initiates handshake so virtio-serial never drops early host frames before port open.
    send_message(
        writer,
        StreamId(0),
        &Message::Hello {
            version: PROTOCOL_VERSION,
        },
    )?;

    let ack_frame = read_frame(reader)?;
    if ack_frame.header.stream_id != StreamId(0) {
        return Err(ProtocolError::InvalidPayload(format!(
            "expected HelloAck on stream 0, got {}",
            ack_frame.header.stream_id
        )));
    }
    match ack_frame.decode_message()? {
        Message::HelloAck { version, .. } if version == PROTOCOL_VERSION => {}
        Message::HelloAck { version, .. } => {
            return Err(ProtocolError::UnsupportedVersion(version));
        }
        other => {
            return Err(ProtocolError::InvalidPayload(format!(
                "expected HelloAck during handshake, got {:?}",
                other.kind()
            )));
        }
    }

    loop {
        let frame = match read_frame(reader) {
            Ok(frame) => frame,
            Err(ProtocolError::Eof) => return Ok(()),
            Err(err) => return Err(err),
        };
        let stream_id = frame.header.stream_id;
        match frame.decode_message()? {
            Message::Ping { seq } => {
                send_message(writer, stream_id, &Message::Pong { seq })?;
            }
            Message::ExecStart { argv } => {
                handle_exec(writer, stream_id, &argv)?;
            }
            Message::Shutdown => {
                send_message(writer, StreamId(0), &Message::Shutdown)?;
                return Ok(());
            }
            other => {
                return Err(ProtocolError::InvalidPayload(format!(
                    "unsupported message {:?} in Phase 1 spike session",
                    other.kind()
                )));
            }
        }
    }
}

fn handle_exec<W: Write>(
    writer: &mut W,
    stream_id: StreamId,
    argv: &[String],
) -> Result<(), ProtocolError> {
    let Some((program, args)) = argv.split_first() else {
        return Err(ProtocolError::InvalidPayload(
            "ExecStart argv must not be empty".to_owned(),
        ));
    };

    // shortcut: buffers stdout/stderr in memory via Command::output for Phase 1 spike, Phase 3 supervisor streams incremental pipe chunks and kills process group on deadline
    let (stdout, stderr, exit_code) = match Command::new(program).args(args).output() {
        Ok(output) => {
            let code = output.status.code().unwrap_or(-1);
            (output.stdout, output.stderr, code)
        }
        Err(err) => {
            let code = if err.kind() == io::ErrorKind::PermissionDenied {
                126
            } else {
                127
            };
            let msg = format!("failed to execute '{program}': {err}\n");
            (Vec::new(), msg.into_bytes(), code)
        }
    };

    send_stream_bytes(writer, stream_id, StreamChannel::Stdout, &stdout)?;
    send_stream_bytes(writer, stream_id, StreamChannel::Stderr, &stderr)?;
    send_message(writer, stream_id, &Message::ExecExit { code: exit_code })?;
    Ok(())
}

fn send_stream_bytes<W: Write>(
    writer: &mut W,
    stream_id: StreamId,
    channel: StreamChannel,
    bytes: &[u8],
) -> Result<(), ProtocolError> {
    if bytes.is_empty() {
        return send_message(
            writer,
            stream_id,
            &Message::StreamData {
                channel,
                eof: true,
                data: Vec::new(),
            },
        );
    }

    let mut chunks = bytes.chunks(MAX_STREAM_DATA_CHUNK_BYTES).peekable();
    while let Some(chunk) = chunks.next() {
        let eof = chunks.peek().is_none();
        send_message(
            writer,
            stream_id,
            &Message::StreamData {
                channel,
                eof,
                data: chunk.to_vec(),
            },
        )?;
    }
    Ok(())
}

fn send_message<W: Write>(
    writer: &mut W,
    stream_id: StreamId,
    msg: &Message,
) -> Result<(), ProtocolError> {
    let frame = Frame::from_message(stream_id, msg)?;
    write_frame(writer, &frame)
}

fn open_virtio_port() -> io::Result<(std::fs::File, &'static str)> {
    let deadline = Instant::now() + PORT_OPEN_TIMEOUT;
    let mut last_err = None;
    loop {
        for &path in &VIRTIO_PORT_CANDIDATES {
            match OpenOptions::new().read(true).write(true).open(path) {
                Ok(file) => return Ok((file, path)),
                Err(err) => last_err = Some(err),
            }
        }
        if Instant::now() >= deadline {
            return Err(last_err.unwrap_or_else(|| {
                io::Error::new(io::ErrorKind::NotFound, "no virtio-serial port available")
            }));
        }
        thread::sleep(PORT_OPEN_POLL_INTERVAL);
    }
}

fn main() -> ExitCode {
    let (mut reader, path) = match open_virtio_port() {
        Ok(port) => port,
        Err(err) => {
            eprintln!("[sandbox-agent] failed to open virtio-serial port: {err}");
            return ExitCode::FAILURE;
        }
    };
    let mut writer = match reader.try_clone() {
        Ok(dup) => dup,
        Err(err) => {
            eprintln!("[sandbox-agent] failed to clone virtio-serial handle for {path}: {err}");
            return ExitCode::FAILURE;
        }
    };

    eprintln!("[sandbox-agent] connected on {path}");
    match serve_session(&mut reader, &mut writer) {
        Ok(()) => {
            eprintln!("[sandbox-agent] session exited cleanly");
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("[sandbox-agent] session error: {err}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::io::Cursor;
    use std::sync::mpsc::{self, Receiver, Sender};

    struct ChannelReader {
        rx: Receiver<Vec<u8>>,
        buf: VecDeque<u8>,
    }

    impl Read for ChannelReader {
        fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
            while self.buf.is_empty() {
                match self.rx.recv() {
                    Ok(chunk) if chunk.is_empty() => continue,
                    Ok(chunk) => self.buf.extend(chunk),
                    Err(_) => return Ok(0),
                }
            }
            let n = out.len().min(self.buf.len());
            for slot in &mut out[..n] {
                *slot = self.buf.pop_front().expect("checked non-empty");
            }
            Ok(n)
        }
    }

    struct ChannelWriter {
        tx: Sender<Vec<u8>>,
    }

    impl Write for ChannelWriter {
        fn write(&mut self, data: &[u8]) -> io::Result<usize> {
            self.tx
                .send(data.to_vec())
                .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "channel closed"))?;
            Ok(data.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn duplex_pair() -> ((ChannelReader, ChannelWriter), (ChannelReader, ChannelWriter)) {
        let (a_to_b_tx, a_to_b_rx) = mpsc::channel();
        let (b_to_a_tx, b_to_a_rx) = mpsc::channel();
        (
            (
                ChannelReader {
                    rx: b_to_a_rx,
                    buf: VecDeque::new(),
                },
                ChannelWriter { tx: a_to_b_tx },
            ),
            (
                ChannelReader {
                    rx: a_to_b_rx,
                    buf: VecDeque::new(),
                },
                ChannelWriter { tx: b_to_a_tx },
            ),
        )
    }

    fn shell_cmd(script: &str) -> Vec<String> {
        #[cfg(windows)]
        {
            vec!["cmd".to_owned(), "/C".to_owned(), script.to_owned()]
        }
        #[cfg(unix)]
        {
            vec!["/bin/sh".to_owned(), "-c".to_owned(), script.to_owned()]
        }
    }

    fn encode_frames(items: &[(StreamId, Message)]) -> Vec<u8> {
        let mut wire = Vec::new();
        for (stream_id, msg) in items {
            let frame = Frame::from_message(*stream_id, msg).expect("valid test frame");
            write_frame(&mut wire, &frame).expect("encode to vec");
        }
        wire
    }

    #[test]
    fn interactive_session_handles_handshake_ping_exec_and_shutdown() {
        let ((mut host_rx, mut host_tx), (mut agent_rx, mut agent_tx)) = duplex_pair();
        let agent = thread::spawn(move || serve_session(&mut agent_rx, &mut agent_tx));

        // 1. Guest initiates handshake before host writes anything.
        let hello = read_frame(&mut host_rx).expect("guest must emit Hello first");
        assert_eq!(hello.header.stream_id, StreamId(0));
        assert_eq!(
            hello.decode_message().unwrap(),
            Message::Hello {
                version: PROTOCOL_VERSION
            }
        );

        send_message(
            &mut host_tx,
            StreamId(0),
            &Message::HelloAck {
                version: PROTOCOL_VERSION,
                features: 0,
            },
        )
        .unwrap();

        // 2. Ping / Pong preserves arbitrary StreamId.
        send_message(&mut host_tx, StreamId(9), &Message::Ping { seq: 1234 }).unwrap();
        let pong = read_frame(&mut host_rx).expect("Pong expected");
        assert_eq!(pong.header.stream_id, StreamId(9));
        assert_eq!(pong.decode_message().unwrap(), Message::Pong { seq: 1234 });

        // 3. ExecStart runs a real command producing stdout, stderr, and non-zero exit code.
        #[cfg(windows)]
        let script = "echo hello-out& echo hello-err 1>&2& exit /b 7";
        #[cfg(unix)]
        let script = "printf 'hello-out\\n'; printf 'hello-err\\n' >&2; exit 7";

        send_message(
            &mut host_tx,
            StreamId(11),
            &Message::ExecStart {
                argv: shell_cmd(script),
            },
        )
        .unwrap();

        let mut stdout_bytes = Vec::new();
        let mut stderr_bytes = Vec::new();
        let mut stdout_eof = false;
        let mut stderr_eof = false;
        let exit_code = loop {
            let frame = read_frame(&mut host_rx).expect("exec response frame");
            assert_eq!(frame.header.stream_id, StreamId(11));
            match frame.decode_message().unwrap() {
                Message::StreamData {
                    channel: StreamChannel::Stdout,
                    eof,
                    data,
                } => {
                    stdout_bytes.extend_from_slice(&data);
                    if eof {
                        stdout_eof = true;
                    }
                }
                Message::StreamData {
                    channel: StreamChannel::Stderr,
                    eof,
                    data,
                } => {
                    stderr_bytes.extend_from_slice(&data);
                    if eof {
                        stderr_eof = true;
                    }
                }
                Message::ExecExit { code } => break code,
                other => panic!("unexpected frame during exec: {other:?}"),
            }
        };
        assert!(stdout_eof && stderr_eof);
        assert_eq!(exit_code, 7);
        assert!(
            String::from_utf8_lossy(&stdout_bytes).contains("hello-out"),
            "stdout was {:?}",
            String::from_utf8_lossy(&stdout_bytes)
        );
        assert!(
            String::from_utf8_lossy(&stderr_bytes).contains("hello-err"),
            "stderr was {:?}",
            String::from_utf8_lossy(&stderr_bytes)
        );

        // 4. Missing binary reports error on stderr and exit code 127.
        send_message(
            &mut host_tx,
            StreamId(12),
            &Message::ExecStart {
                argv: vec!["minipod_nonexistent_binary_99999".to_owned()],
            },
        )
        .unwrap();

        let f_out = read_frame(&mut host_rx).unwrap();
        assert_eq!(f_out.header.stream_id, StreamId(12));
        assert_eq!(
            f_out.decode_message().unwrap(),
            Message::StreamData {
                channel: StreamChannel::Stdout,
                eof: true,
                data: Vec::new(),
            }
        );

        let f_err = read_frame(&mut host_rx).unwrap();
        assert_eq!(f_err.header.stream_id, StreamId(12));
        match f_err.decode_message().unwrap() {
            Message::StreamData {
                channel: StreamChannel::Stderr,
                eof: true,
                data,
            } => {
                assert!(!data.is_empty(), "expected spawn failure message on stderr");
            }
            other => panic!("expected stderr frame, got {other:?}"),
        }

        let f_exit = read_frame(&mut host_rx).unwrap();
        assert_eq!(f_exit.header.stream_id, StreamId(12));
        assert_eq!(
            f_exit.decode_message().unwrap(),
            Message::ExecExit { code: 127 }
        );

        // 5. Shutdown acks on StreamId(0) and exits loop cleanly.
        send_message(&mut host_tx, StreamId(0), &Message::Shutdown).unwrap();
        let ack = read_frame(&mut host_rx).unwrap();
        assert_eq!(ack.header.stream_id, StreamId(0));
        assert_eq!(ack.decode_message().unwrap(), Message::Shutdown);

        drop(host_tx);
        agent.join().expect("agent thread did not panic").unwrap();
    }

    #[test]
    fn handshake_rejects_mismatched_version_and_non_ack() {
        let bad_ver = encode_frames(&[(
            StreamId(0),
            Message::HelloAck {
                version: PROTOCOL_VERSION + 1,
                features: 0,
            },
        )]);
        let mut reader = Cursor::new(bad_ver);
        let mut writer = Vec::new();
        assert_eq!(
            serve_session(&mut reader, &mut writer),
            Err(ProtocolError::UnsupportedVersion(PROTOCOL_VERSION + 1))
        );

        let wrong_msg = encode_frames(&[(StreamId(0), Message::Ping { seq: 1 })]);
        let mut reader = Cursor::new(wrong_msg);
        let mut writer = Vec::new();
        assert!(matches!(
            serve_session(&mut reader, &mut writer),
            Err(ProtocolError::InvalidPayload(_))
        ));
    }

    #[test]
    fn clean_eof_after_handshake_exits_ok() {
        let input = encode_frames(&[(
            StreamId(0),
            Message::HelloAck {
                version: PROTOCOL_VERSION,
                features: 0,
            },
        )]);
        let mut reader = Cursor::new(input);
        let mut writer = Vec::new();
        serve_session(&mut reader, &mut writer).expect("clean EOF should return Ok(())");

        let mut out_cursor = Cursor::new(writer);
        let hello = read_frame(&mut out_cursor).unwrap();
        assert_eq!(
            hello.decode_message().unwrap(),
            Message::Hello {
                version: PROTOCOL_VERSION
            }
        );
        assert_eq!(read_frame(&mut out_cursor), Err(ProtocolError::Eof));
    }

    #[test]
    fn send_stream_bytes_chunks_large_output_within_frame_limit() {
        let payload = vec![b'x'; MAX_STREAM_DATA_CHUNK_BYTES + 17];
        let mut wire = Vec::new();
        send_stream_bytes(&mut wire, StreamId(5), StreamChannel::Stdout, &payload)
            .expect("chunking must fit within MAX_FRAME_PAYLOAD_BYTES");

        let mut cursor = Cursor::new(wire);
        let first = read_frame(&mut cursor).unwrap();
        assert_eq!(first.header.stream_id, StreamId(5));
        assert_eq!(
            first.decode_message().unwrap(),
            Message::StreamData {
                channel: StreamChannel::Stdout,
                eof: false,
                data: vec![b'x'; MAX_STREAM_DATA_CHUNK_BYTES],
            }
        );

        let second = read_frame(&mut cursor).unwrap();
        assert_eq!(second.header.stream_id, StreamId(5));
        assert_eq!(
            second.decode_message().unwrap(),
            Message::StreamData {
                channel: StreamChannel::Stdout,
                eof: true,
                data: vec![b'x'; 17],
            }
        );

        assert_eq!(read_frame(&mut cursor), Err(ProtocolError::Eof));
    }
}
