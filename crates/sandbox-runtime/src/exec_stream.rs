//! Async streaming I/O channels and cancellation control for guest/container execution.

use std::time::Duration;

use sandbox_core::{ExecExitStatus, SandboxError};
use sandbox_protocol::StreamId;
use tokio::sync::{mpsc, oneshot};
use tokio::time::Instant;

const STDIN_CHANNEL_CAPACITY: usize = 64;
const OUTPUT_CHANNEL_CAPACITY: usize = 256;
const CANCEL_CHANNEL_CAPACITY: usize = 1;
const MIN_EXIT_DRAIN_GRACE: Duration = Duration::from_millis(100);
const MAX_EXIT_DRAIN_GRACE: Duration = Duration::from_secs(2);

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

#[derive(Clone, Copy, Debug)]
struct HostExecLimits {
    deadline_duration: Duration,
    deadline_at: Option<Instant>,
    stdout_budget_bytes: u64,
    stderr_budget_bytes: u64,
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
    limits: Option<HostExecLimits>,
    stdout_seen: u64,
    stderr_seen: u64,
    host_timed_out: bool,
    host_stdout_truncated: bool,
    host_stderr_truncated: bool,
    output_stopped: bool,
}

/// Standalone sender handle for writing execution `stdin` chunks or closing `stdin` independently
/// of output/cancellation polling.
#[derive(Clone, Debug)]
pub struct ExecStdinWriter {
    stdin_tx: Option<mpsc::Sender<Vec<u8>>>,
}

impl ExecStdinWriter {
    /// Sends a chunk of bytes to the execution's `stdin` stream.
    pub async fn write(&self, data: Vec<u8>) -> Result<(), SandboxError> {
        let Some(tx) = &self.stdin_tx else {
            return Err(SandboxError::Transport(
                "execution stdin stream is already closed".to_owned(),
            ));
        };
        tx.send(data)
            .await
            .map_err(|_| SandboxError::Transport("execution stdin receiver closed".to_owned()))
    }

    /// Closes this `stdin` sender handle, signalling EOF if no other clones remain.
    pub fn close(&mut self) {
        self.stdin_tx = None;
    }
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
            limits: None,
            stdout_seen: 0,
            stderr_seen: 0,
            host_timed_out: false,
            host_stdout_truncated: false,
            host_stderr_truncated: false,
            output_stopped: false,
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

    /// Attaches host-enforced `deadline`, `stdout_budget_bytes`, and `stderr_budget_bytes` ceilings
    /// so untrusted or hung guest supervisors cannot exceed host memory or stall callers indefinitely.
    pub fn with_limits(
        mut self,
        deadline: Duration,
        stdout_budget_bytes: u64,
        stderr_budget_bytes: u64,
    ) -> Self {
        if self.limits.is_none() {
            self.limits = Some(HostExecLimits {
                deadline_duration: deadline,
                deadline_at: Instant::now().checked_add(deadline),
                stdout_budget_bytes,
                stderr_budget_bytes,
            });
        }
        self
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

    /// Detaches ownership of the `stdin` sender into an [`ExecStdinWriter`] so a dedicated
    /// task can forward `stdin` chunks without stalling cancellation or deadline polling.
    pub fn take_stdin_writer(&mut self) -> ExecStdinWriter {
        ExecStdinWriter {
            stdin_tx: self.stdin_tx.take(),
        }
    }

    /// Receives the next incremental `stdout` or `stderr` chunk, or `None` once output closes
    /// or host `deadline` / output budget limits are reached.
    pub async fn next_output(&mut self) -> Option<ExecOutputChunk> {
        if self.output_stopped {
            return None;
        }

        let maybe_deadline = self.limits.and_then(|l| l.deadline_at);
        let recv_chunk = match maybe_deadline {
            Some(deadline_at) => {
                if Instant::now() >= deadline_at {
                    self.trip_host_timeout();
                    return None;
                }
                tokio::select! {
                    biased;
                    _ = tokio::time::sleep_until(deadline_at) => {
                        self.trip_host_timeout();
                        return None;
                    }
                    chunk = self.output_rx.recv() => chunk,
                }
            }
            None => self.output_rx.recv().await,
        };

        let mut chunk = recv_chunk?;
        let Some(limits) = self.limits else {
            return Some(chunk);
        };

        let (seen, budget, is_stdout) = match chunk.stream {
            OutputStreamKind::Stdout => (&mut self.stdout_seen, limits.stdout_budget_bytes, true),
            OutputStreamKind::Stderr => (&mut self.stderr_seen, limits.stderr_budget_bytes, false),
        };

        let remaining = budget.saturating_sub(*seen);
        if (chunk.data.len() as u64) <= remaining {
            *seen = seen.saturating_add(chunk.data.len() as u64);
            return Some(chunk);
        }

        let allowed = usize::try_from(remaining).unwrap_or(usize::MAX);
        chunk.data.truncate(allowed);
        *seen = budget;
        if is_stdout {
            self.host_stdout_truncated = true;
        } else {
            self.host_stderr_truncated = true;
        }
        self.stop_and_cancel_from_host();
        if chunk.data.is_empty() {
            None
        } else {
            Some(chunk)
        }
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
    ///
    /// If the caller has not drained `stdout`/`stderr` via [`Self::next_output`], unread output
    /// chunks are discarded while awaiting exit so bounded output channels cannot deadlock the
    /// producer before `ExecExit` is delivered.
    pub async fn wait_exit(&mut self) -> Result<ExecExitStatus, SandboxError> {
        if let Some(res) = &self.cached_exit {
            return res.clone();
        }
        let Some(mut rx) = self.exit_rx.take() else {
            return Err(SandboxError::Internal(
                "execution exit status receiver unavailable".to_owned(),
            ));
        };

        let res = match rx.try_recv() {
            Ok(status) => self.merge_host_exit(status),
            Err(oneshot::error::TryRecvError::Closed) if self.host_tripped() => {
                Ok(self.synthesized_host_exit())
            }
            Err(oneshot::error::TryRecvError::Closed) => Err(SandboxError::Transport(
                "execution stream terminated before reporting exit status".to_owned(),
            )),
            Err(oneshot::error::TryRecvError::Empty) => self.await_exit_receiver(&mut rx).await,
        };
        self.cached_exit = Some(res.clone());
        res
    }

    /// Closes `stdin`, drains all remaining `stdout`/`stderr` chunks within configured budgets,
    /// and awaits exit status.
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

    fn host_tripped(&self) -> bool {
        self.host_timed_out || self.host_stdout_truncated || self.host_stderr_truncated
    }

    fn exit_drain_grace(&self) -> Duration {
        match self.limits {
            Some(limits) => limits
                .deadline_duration
                .min(MAX_EXIT_DRAIN_GRACE)
                .max(MIN_EXIT_DRAIN_GRACE),
            None => MAX_EXIT_DRAIN_GRACE,
        }
    }

    fn stop_and_cancel_from_host(&mut self) {
        self.output_stopped = true;
        self.stdin_tx = None;
        self.output_rx.close();
        let _ = self.cancel();
    }

    fn trip_host_timeout(&mut self) {
        self.host_timed_out = true;
        self.stop_and_cancel_from_host();
    }

    fn merge_host_exit(
        &self,
        result: Result<ExecExitStatus, SandboxError>,
    ) -> Result<ExecExitStatus, SandboxError> {
        match result {
            Ok(mut status) => {
                if self.host_tripped() && status.code == Some(0) {
                    status.code = None;
                }
                status.timed_out |= self.host_timed_out;
                status.stdout_truncated |= self.host_stdout_truncated;
                status.stderr_truncated |= self.host_stderr_truncated;
                Ok(status)
            }
            Err(err) => Err(err),
        }
    }

    fn synthesized_host_exit(&self) -> ExecExitStatus {
        ExecExitStatus {
            code: None,
            timed_out: self.host_timed_out,
            stdout_truncated: self.host_stdout_truncated,
            stderr_truncated: self.host_stderr_truncated,
        }
    }

    fn account_discarded_chunk(&mut self, chunk: &ExecOutputChunk) {
        let Some(limits) = self.limits else {
            return;
        };
        let (seen, budget, is_stdout) = match chunk.stream {
            OutputStreamKind::Stdout => (&mut self.stdout_seen, limits.stdout_budget_bytes, true),
            OutputStreamKind::Stderr => (&mut self.stderr_seen, limits.stderr_budget_bytes, false),
        };
        let next = seen.saturating_add(chunk.data.len() as u64);
        if next > budget {
            *seen = budget;
            if is_stdout {
                self.host_stdout_truncated = true;
            } else {
                self.host_stderr_truncated = true;
            }
            self.stop_and_cancel_from_host();
        } else {
            *seen = next;
        }
    }

    async fn await_exit_receiver(
        &mut self,
        rx: &mut oneshot::Receiver<Result<ExecExitStatus, SandboxError>>,
    ) -> Result<ExecExitStatus, SandboxError> {
        if !self.host_tripped() {
            let maybe_deadline = self.limits.and_then(|l| l.deadline_at);
            let mut output_open = !self.output_stopped;
            loop {
                tokio::select! {
                    biased;
                    exit_res = &mut *rx => {
                        return match exit_res {
                            Ok(status) => self.merge_host_exit(status),
                            Err(_) => Err(SandboxError::Transport(
                                "execution stream terminated before reporting exit status".to_owned(),
                            )),
                        };
                    }
                    _ = async {
                        match maybe_deadline {
                            Some(dl) => tokio::time::sleep_until(dl).await,
                            None => std::future::pending::<()>().await,
                        }
                    }, if maybe_deadline.is_some() => {
                        self.trip_host_timeout();
                        break;
                    }
                    chunk = self.output_rx.recv(), if output_open => {
                        match chunk {
                            Some(c) => {
                                self.account_discarded_chunk(&c);
                                if self.host_tripped() {
                                    break;
                                }
                            }
                            None => {
                                output_open = false;
                                if maybe_deadline.is_none() {
                                    return match rx.await {
                                        Ok(status) => self.merge_host_exit(status),
                                        Err(_) => Err(SandboxError::Transport(
                                            "execution stream terminated before reporting exit status".to_owned(),
                                        )),
                                    };
                                }
                            }
                        }
                    }
                }
            }
        }

        let grace = self.exit_drain_grace();
        match tokio::time::timeout(grace, rx).await {
            Ok(Ok(status)) => self.merge_host_exit(status),
            Ok(Err(_)) => Ok(self.synthesized_host_exit()),
            Err(_) => Ok(self.synthesized_host_exit()),
        }
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

    #[tokio::test]
    async fn exec_stream_wait_exit_drains_unread_output_above_channel_capacity() {
        let (mut stream, handle) = ExecStream::channel(StreamId(23));

        let producer = tokio::spawn(async move {
            for _ in 0..(OUTPUT_CHANNEL_CAPACITY + 32) {
                handle
                    .send_output(ExecOutputChunk {
                        stream: OutputStreamKind::Stdout,
                        data: b"x".to_vec(),
                    })
                    .await
                    .expect("wait_exit must drain output_rx so producer does not deadlock");
            }
            handle.finish(Ok(ExecExitStatus {
                code: Some(0),
                timed_out: false,
                stdout_truncated: false,
                stderr_truncated: false,
            }));
        });

        let exit = tokio::time::timeout(std::time::Duration::from_secs(2), stream.wait_exit())
            .await
            .expect("wait_exit must not hang when output exceeds channel capacity")
            .unwrap();
        assert_eq!(exit.code, Some(0));
        producer.await.unwrap();
    }

    #[tokio::test]
    async fn exec_stream_with_limits_caps_rogue_output_and_deadlines_without_guest_exit() {
        // 1. Rogue guest floods stdout past budget and never sends ExecExit.
        let (stream, mut handle) = ExecStream::channel(StreamId(31));
        let stream = stream.with_limits(Duration::from_millis(200), 10, 8);

        let rogue_flood = tokio::spawn(async move {
            let _ = handle
                .send_output(ExecOutputChunk {
                    stream: OutputStreamKind::Stdout,
                    data: b"0123456789ABCDEF".to_vec(),
                })
                .await;
            assert_eq!(
                handle.recv_cancel().await,
                Some(()),
                "host budget breach must emit cancel signal"
            );
            // Intentionally keep `handle` alive without calling `finish` for 5s.
            tokio::time::sleep(Duration::from_secs(5)).await;
        });

        let collected = tokio::time::timeout(Duration::from_secs(2), stream.collect())
            .await
            .expect("host budget cap must not hang when guest ignores ExecCancel")
            .unwrap();
        assert_eq!(collected.stdout, b"0123456789");
        assert!(collected.exit.stdout_truncated);
        assert!(!collected.exit.stderr_truncated);
        assert!(!collected.exit.timed_out);
        assert_eq!(collected.exit.code, None);
        rogue_flood.abort();

        // 2. Rogue guest stalls silently forever past deadline without sending ExecExit.
        let (silent_stream, mut silent_handle) = ExecStream::channel(StreamId(33));
        let silent_stream = silent_stream.with_limits(Duration::from_millis(60), 1024, 1024);

        let silent_task = tokio::spawn(async move {
            assert_eq!(
                silent_handle.recv_cancel().await,
                Some(()),
                "host deadline must emit cancel signal"
            );
            tokio::time::sleep(Duration::from_secs(5)).await;
        });

        let timed_out = tokio::time::timeout(Duration::from_secs(2), silent_stream.collect())
            .await
            .expect("host deadline must resolve even when guest never sends ExecExit")
            .unwrap();
        assert!(timed_out.stdout.is_empty());
        assert!(timed_out.exit.timed_out);
        assert_eq!(timed_out.exit.code, None);
        silent_task.abort();

        // 3. Budget trip followed by immediate producer drop (TryRecvError::Closed before wait_exit).
        let (stream_closed, handle_closed) = ExecStream::channel(StreamId(34));
        let mut stream_closed = stream_closed.with_limits(Duration::from_secs(5), 4, 4);
        let _ = handle_closed
            .send_output(ExecOutputChunk {
                stream: OutputStreamKind::Stdout,
                data: b"123456".to_vec(),
            })
            .await;
        drop(handle_closed);

        let first = stream_closed.next_output().await.expect("capped chunk expected");
        assert_eq!(first.data, b"1234");
        assert!(stream_closed.next_output().await.is_none());
        let closed_exit = stream_closed.wait_exit().await.unwrap();
        assert!(closed_exit.stdout_truncated);
        assert_eq!(closed_exit.code, None);
    }
}
