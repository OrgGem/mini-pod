//! Async streaming I/O channels and cancellation control for guest/container execution.

use sandbox_core::{ExecExitStatus, SandboxError};
use sandbox_protocol::StreamId;
use tokio::sync::{mpsc, oneshot};

const STDIN_CHANNEL_CAPACITY: usize = 64;
const OUTPUT_CHANNEL_CAPACITY: usize = 256;
const CANCEL_CHANNEL_CAPACITY: usize = 1;

/// Identifies whether an execution output chunk originated on guest `stdout` or `stderr`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OutputStreamKind {
    Stdout,
    Stderr,
}

/// Incremental output chunk emitted by an in-flight sandbox execution.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecOutputChunk {
    pub stream: OutputStreamKind,
    pub data: Vec<u8>,
}

/// Aggregated output and terminal exit status collected from an [`ExecStream`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CollectedExecOutput {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub exit: ExecExitStatus,
}

/// Caller-side bidirectional handle to an active guest or container execution stream.
#[derive(Debug)]
pub struct ExecStream {
    pub stream_id: StreamId,
    stdin_tx: Option<mpsc::Sender<Vec<u8>>>,
    output_rx: mpsc::Receiver<ExecOutputChunk>,
    cancel_tx: mpsc::Sender<()>,
    exit_rx: Option<oneshot::Receiver<Result<ExecExitStatus, SandboxError>>>,
    cached_exit: Option<Result<ExecExitStatus, SandboxError>>,
}

/// Driver-side handle used by `VmSessionPort` implementations to pump stdin, output, cancel,
/// and final exit status for a corresponding [`ExecStream`].
#[derive(Debug)]
pub struct ExecStreamHandle {
    pub stream_id: StreamId,
    pub stdin_rx: mpsc::Receiver<Vec<u8>>,
    pub output_tx: mpsc::Sender<ExecOutputChunk>,
    pub cancel_rx: mpsc::Receiver<()>,
    pub exit_tx: Option<oneshot::Sender<Result<ExecExitStatus, SandboxError>>>,
}

impl ExecStream {
    /// Creates a connected `(`[`ExecStream`]`, `[`ExecStreamHandle`]`)` channel pair for `stream_id`.
    pub fn channel(stream_id: StreamId) -> (Self, ExecStreamHandle) {
        let (stdin_tx, stdin_rx) = mpsc::channel(STDIN_CHANNEL_CAPACITY);
        let (output_tx, output_rx) = mpsc::channel(OUTPUT_CHANNEL_CAPACITY);
        let (cancel_tx, cancel_rx) = mpsc::channel(CANCEL_CHANNEL_CAPACITY);
        let (exit_tx, exit_rx) = oneshot::channel();

        let stream = Self {
            stream_id,
            stdin_tx: Some(stdin_tx),
            output_rx,
            cancel_tx,
            exit_rx: Some(exit_rx),
            cached_exit: None,
        };
        let handle = ExecStreamHandle {
            stream_id,
            stdin_rx,
            output_tx,
            cancel_rx,
            exit_tx: Some(exit_tx),
        };
        (stream, handle)
    }

    /// Sends a chunk of bytes to the execution's `stdin` stream.
    pub async fn write_stdin(&self, data: Vec<u8>) -> Result<(), SandboxError> {
        let Some(tx) = &self.stdin_tx else {
            return Err(SandboxError::Transport(
                "execution stdin stream is already closed".to_owned(),
            ));
        };
        tx.send(data)
            .await
            .map_err(|_| SandboxError::Transport("execution stdin receiver closed".to_owned()))
    }

    /// Closes the caller's `stdin` sender, signalling EOF to the VM session driver.
    pub fn close_stdin(&mut self) {
        self.stdin_tx = None;
    }

    /// Receives the next incremental `stdout` or `stderr` chunk, or `None` once output closes.
    pub async fn next_output(&mut self) -> Option<ExecOutputChunk> {
        self.output_rx.recv().await
    }

    /// Signals cancellation so the host VM driver transmits `Message::ExecCancel`.
    pub fn cancel(&self) -> Result<(), SandboxError> {
        match self.cancel_tx.try_send(()) {
            Ok(()) | Err(mpsc::error::TrySendError::Full(())) => Ok(()),
            Err(mpsc::error::TrySendError::Closed(())) => Err(SandboxError::Transport(
                "execution stream already closed".to_owned(),
            )),
        }
    }

    /// Waits for the execution's terminal [`ExecExitStatus`] or transport/execution failure.
    pub async fn wait_exit(&mut self) -> Result<ExecExitStatus, SandboxError> {
        if let Some(res) = &self.cached_exit {
            return res.clone();
        }
        let Some(rx) = self.exit_rx.take() else {
            return Err(SandboxError::Internal(
                "execution exit status receiver unavailable".to_owned(),
            ));
        };
        let res = match rx.await {
            Ok(status) => status,
            Err(_) => Err(SandboxError::Transport(
                "execution stream terminated before reporting exit status".to_owned(),
            )),
        };
        self.cached_exit = Some(res.clone());
        res
    }

    /// Closes `stdin`, drains all remaining `stdout`/`stderr` chunks, and awaits exit status.
    pub async fn collect(mut self) -> Result<CollectedExecOutput, SandboxError> {
        self.close_stdin();
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        while let Some(chunk) = self.next_output().await {
            match chunk.stream {
                OutputStreamKind::Stdout => stdout.extend_from_slice(&chunk.data),
                OutputStreamKind::Stderr => stderr.extend_from_slice(&chunk.data),
            }
        }

        let exit = self.wait_exit().await?;
        Ok(CollectedExecOutput {
            stdout,
            stderr,
            exit,
        })
    }
}

impl ExecStreamHandle {
    /// Emits an output chunk toward the caller's [`ExecStream`].
    pub async fn send_output(&self, chunk: ExecOutputChunk) -> Result<(), SandboxError> {
        self.output_tx
            .send(chunk)
            .await
            .map_err(|_| SandboxError::Transport("execution output receiver dropped".to_owned()))
    }

    /// Receives the next `stdin` chunk, or `None` once [`ExecStream::close_stdin`] / drop occurs.
    pub async fn recv_stdin(&mut self) -> Option<Vec<u8>> {
        self.stdin_rx.recv().await
    }

    /// Waits for a cancellation signal from [`ExecStream::cancel`], or `None` if dropped.
    pub async fn recv_cancel(&mut self) -> Option<()> {
        self.cancel_rx.recv().await
    }

    /// Delivers the final exit result if not already sent; returns `true` when delivered.
    pub fn send_exit(&mut self, result: Result<ExecExitStatus, SandboxError>) -> bool {
        let Some(tx) = self.exit_tx.take() else {
            return false;
        };
        tx.send(result).is_ok()
    }

    /// Delivers `result` and drops the driver handle, closing output channels cleanly.
    pub fn finish(mut self, result: Result<ExecExitStatus, SandboxError>) {
        self.send_exit(result);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn exec_stream_stdin_output_and_collect_roundtrip() {
        let (mut stream, mut handle) = ExecStream::channel(StreamId(7));
        assert_eq!(stream.stream_id, StreamId(7));

        let driver = tokio::spawn(async move {
            let mut received_stdin = Vec::new();
            while let Some(chunk) = handle.recv_stdin().await {
                received_stdin.extend_from_slice(&chunk);
            }
            assert_eq!(received_stdin, b"hello world");

            handle
                .send_output(ExecOutputChunk {
                    stream: OutputStreamKind::Stdout,
                    data: b"out-1 ".to_vec(),
                })
                .await
                .unwrap();
            handle
                .send_output(ExecOutputChunk {
                    stream: OutputStreamKind::Stderr,
                    data: b"err-1".to_vec(),
                })
                .await
                .unwrap();
            handle
                .send_output(ExecOutputChunk {
                    stream: OutputStreamKind::Stdout,
                    data: b"out-2".to_vec(),
                })
                .await
                .unwrap();

            handle.finish(Ok(ExecExitStatus {
                code: Some(0),
                timed_out: false,
                stdout_truncated: false,
                stderr_truncated: false,
            }));
        });

        stream.write_stdin(b"hello ".to_vec()).await.unwrap();
        stream.write_stdin(b"world".to_vec()).await.unwrap();
        stream.close_stdin();
        assert!(matches!(
            stream.write_stdin(b"late".to_vec()).await,
            Err(SandboxError::Transport(_))
        ));

        let first = stream.next_output().await.expect("first output chunk");
        assert_eq!(first.stream, OutputStreamKind::Stdout);
        assert_eq!(first.data, b"out-1 ");

        let collected = stream.collect().await.unwrap();
        assert_eq!(collected.stdout, b"out-2");
        assert_eq!(collected.stderr, b"err-1");
        assert_eq!(collected.exit.code, Some(0));
        assert!(!collected.exit.timed_out);

        driver.await.unwrap();
    }

    #[tokio::test]
    async fn exec_stream_cancel_signals_handle_and_is_idempotent() {
        let (mut stream, mut handle) = ExecStream::channel(StreamId(11));

        stream.cancel().unwrap();
        stream.cancel().unwrap();

        let driver = tokio::spawn(async move {
            assert_eq!(handle.recv_cancel().await, Some(()));
            handle.finish(Ok(ExecExitStatus {
                code: None,
                timed_out: false,
                stdout_truncated: false,
                stderr_truncated: false,
            }));
        });

        let exit = stream.wait_exit().await.unwrap();
        assert_eq!(exit.code, None);
        // Repeated wait_exit returns cached status cleanly.
        assert_eq!(stream.wait_exit().await.unwrap(), exit);

        driver.await.unwrap();
        assert!(matches!(stream.cancel(), Err(SandboxError::Transport(_))));
    }

    #[tokio::test]
    async fn exec_stream_dropped_handle_reports_transport_error() {
        let (mut stream, handle) = ExecStream::channel(StreamId(19));
        drop(handle);

        assert!(stream.next_output().await.is_none());
        assert!(matches!(
            stream.write_stdin(b"data".to_vec()).await,
            Err(SandboxError::Transport(_))
        ));
        assert!(matches!(
            stream.cancel(),
            Err(SandboxError::Transport(_))
        ));
        assert!(matches!(
            stream.wait_exit().await,
            Err(SandboxError::Transport(_))
        ));
    }
}
