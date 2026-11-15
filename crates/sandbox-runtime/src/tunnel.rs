//! Async bidirectional stream bridge for multiplexed guest Podman socket and loopback TCP tunnels.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use sandbox_protocol::StreamId;
use tokio::io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf, ReadHalf, WriteHalf};
use tokio::sync::oneshot;

const TUNNEL_DUPLEX_BUFFER_BYTES: usize = 256 * 1024;

/// Caller-side bidirectional stream connected to a multiplexed guest tunnel (`PodmanUnixSocket` or
/// `GuestLoopbackTcp`).
///
/// Implements [`AsyncRead`] + [`AsyncWrite`] with independent half-close via [`AsyncWrite::poll_shutdown`]
/// and reports whether graceful write shutdown occurred when dropped so the VMM driver can emit
/// [`sandbox_protocol::Message::StreamClose`] on `Lane::Control` on early drop.
#[derive(Debug)]
pub struct TunnelStream {
    stream_id: StreamId,
    io: DuplexStream,
    write_shutdown: bool,
    drop_tx: Option<oneshot::Sender<bool>>,
}

/// Driver-side bridge handles paired with a [`TunnelStream`].
#[derive(Debug)]
pub struct TunnelStreamHandle {
    pub stream_id: StreamId,
    pub read_half: ReadHalf<DuplexStream>,
    pub write_half: WriteHalf<DuplexStream>,
    pub drop_rx: oneshot::Receiver<bool>,
}

impl TunnelStream {
    /// Creates a connected `(`[`TunnelStream`]`, `[`TunnelStreamHandle`]`)` pair for `stream_id`.
    pub fn channel(stream_id: StreamId) -> (Self, TunnelStreamHandle) {
        let (client_io, driver_io) = tokio::io::duplex(TUNNEL_DUPLEX_BUFFER_BYTES);
        let (read_half, write_half) = tokio::io::split(driver_io);
        let (drop_tx, drop_rx) = oneshot::channel();

        let stream = Self {
            stream_id,
            io: client_io,
            write_shutdown: false,
            drop_tx: Some(drop_tx),
        };
        let handle = TunnelStreamHandle {
            stream_id,
            read_half,
            write_half,
            drop_rx,
        };
        (stream, handle)
    }

    /// Returns the protocol `StreamId` assigned to this tunnel.
    pub fn stream_id(&self) -> StreamId {
        self.stream_id
    }
}

impl AsyncRead for TunnelStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_read(cx, buf)
    }
}

impl AsyncWrite for TunnelStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.io).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let poll = Pin::new(&mut self.io).poll_shutdown(cx);
        if let Poll::Ready(Ok(())) = poll {
            self.write_shutdown = true;
        }
        poll
    }
}

impl Drop for TunnelStream {
    fn drop(&mut self) {
        if let Some(tx) = self.drop_tx.take() {
            let _ = tx.send(self.write_shutdown);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn tunnel_stream_preserves_partial_reads_and_independent_half_closes() {
        let (mut stream, mut handle) = TunnelStream::channel(StreamId(7));
        assert_eq!(stream.stream_id(), StreamId(7));

        handle
            .write_half
            .write_all(b"abcdefg")
            .await
            .expect("driver write succeeds");

        // Small buffer reads preserve all remaining unread bytes without loss.
        let mut small = [0u8; 3];
        let mut collected = Vec::new();
        while collected.len() < 7 {
            let n = stream.read(&mut small).await.unwrap();
            assert!(n > 0);
            collected.extend_from_slice(&small[..n]);
        }
        assert_eq!(collected, b"abcdefg");

        // Host shuts down write half while driver keeps writing back.
        stream.write_all(b"ping").await.unwrap();
        stream.shutdown().await.unwrap();

        let mut req = Vec::new();
        handle.read_half.read_to_end(&mut req).await.unwrap();
        assert_eq!(req, b"ping");

        handle.write_half.write_all(b"pong").await.unwrap();
        handle.write_half.shutdown().await.unwrap();

        let mut resp = Vec::new();
        stream.read_to_end(&mut resp).await.unwrap();
        assert_eq!(resp, b"pong");

        drop(stream);
        assert_eq!(handle.drop_rx.await.unwrap(), true);
    }

    #[tokio::test]
    async fn tunnel_stream_early_drop_reports_false_write_shutdown() {
        let (mut stream, handle) = TunnelStream::channel(StreamId(8));
        stream.write_all(b"partial").await.unwrap();
        drop(stream);
        assert_eq!(handle.drop_rx.await.unwrap(), false);
    }
}
