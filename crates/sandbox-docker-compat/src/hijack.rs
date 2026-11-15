//! Full-duplex HTTP `101 UPGRADED` stream relay with independent write half-close.

use std::io;

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

/// Relays an upgraded Docker `exec`/`attach` byte stream bidirectionally between `client` and
/// `upstream`, flushing unconsumed pre-read buffers first and propagating each side's write
/// half-close (`shutdown`) independently.
///
/// Returns `(client_to_upstream_bytes, upstream_to_client_bytes)`.
pub async fn relay_upgraded<C, U>(
    client: C,
    client_pre_buf: &[u8],
    upstream: U,
    upstream_pre_buf: &[u8],
) -> io::Result<(u64, u64)>
where
    C: AsyncRead + AsyncWrite + Unpin,
    U: AsyncRead + AsyncWrite + Unpin,
{
    let (mut cli_read, mut cli_write) = tokio::io::split(client);
    let (mut up_read, mut up_write) = tokio::io::split(upstream);

    let c2u = pump_half(client_pre_buf, &mut cli_read, &mut up_write);
    let u2c = pump_half(upstream_pre_buf, &mut up_read, &mut cli_write);

    tokio::try_join!(c2u, u2c)
}

async fn pump_half<R, W>(pre_buf: &[u8], reader: &mut R, writer: &mut W) -> io::Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut total = 0u64;
    if !pre_buf.is_empty() {
        writer.write_all(pre_buf).await?;
        writer.flush().await?;
        total = total.saturating_add(pre_buf.len() as u64);
    }

    let copied = tokio::io::copy(reader, writer).await?;
    writer.flush().await?;
    writer.shutdown().await?;
    Ok(total.saturating_add(copied))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn relay_upgraded_flushes_prebufs_and_preserves_independent_half_close() {
        let (mut client_peer, proxy_client) = tokio::io::duplex(4096);
        let (proxy_upstream, mut upstream_peer) = tokio::io::duplex(4096);

        let relay_task = tokio::spawn(async move {
            relay_upgraded(proxy_client, b"pre-in:", proxy_upstream, b"pre-out:").await
        });

        // Client sends additional stdin then half-closes its write side (EOF for guest stdin).
        client_peer.write_all(b"stdin-body").await.unwrap();
        client_peer.shutdown().await.unwrap();

        // Upstream reads full stdin until EOF, confirming client half-close reached upstream
        // even while upstream has NOT closed its own stdout yet.
        let mut received_stdin = Vec::new();
        upstream_peer.read_to_end(&mut received_stdin).await.unwrap();
        assert_eq!(received_stdin, b"pre-in:stdin-body");

        // Upstream continues streaming stdout/stderr after receiving stdin EOF, then closes.
        upstream_peer.write_all(b"stdout-after-eof").await.unwrap();
        upstream_peer.shutdown().await.unwrap();

        let mut received_stdout = Vec::new();
        client_peer.read_to_end(&mut received_stdout).await.unwrap();
        assert_eq!(received_stdout, b"pre-out:stdout-after-eof");

        let (c2u_bytes, u2c_bytes) = relay_task
            .await
            .expect("relay task joins")
            .expect("relay succeeds");
        assert_eq!(c2u_bytes, b"pre-in:stdin-body".len() as u64);
        assert_eq!(u2c_bytes, b"pre-out:stdout-after-eof".len() as u64);
    }

    #[tokio::test]
    async fn relay_upgraded_handles_empty_prebufs_and_concurrent_duplex_traffic() {
        let (mut client_peer, proxy_client) = tokio::io::duplex(4096);
        let (proxy_upstream, mut upstream_peer) = tokio::io::duplex(4096);

        let relay_task =
            tokio::spawn(async move { relay_upgraded(proxy_client, &[], proxy_upstream, &[]).await });

        let client_fut = async {
            client_peer.write_all(b"ping-1").await.unwrap();
            let mut buf = [0u8; 6];
            client_peer.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"pong-1");
            client_peer.shutdown().await.unwrap();
            let mut tail = Vec::new();
            client_peer.read_to_end(&mut tail).await.unwrap();
            assert_eq!(tail, b"done");
        };

        let upstream_fut = async {
            let mut buf = [0u8; 6];
            upstream_peer.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"ping-1");
            upstream_peer.write_all(b"pong-1").await.unwrap();

            let mut rest = Vec::new();
            upstream_peer.read_to_end(&mut rest).await.unwrap();
            assert!(rest.is_empty());

            upstream_peer.write_all(b"done").await.unwrap();
            upstream_peer.shutdown().await.unwrap();
        };

        tokio::join!(client_fut, upstream_fut);
        let (c2u, u2c) = relay_task.await.unwrap().unwrap();
        assert_eq!(c2u, 6);
        assert_eq!(u2c, 10);
    }
}
