//! Bidirectional byte copy between two TLS streams.
//! Carried over from ae-egress-proxy (Spike 1) unchanged.

use std::io;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub async fn copy_bidirectional<C, U>(client: &mut C, upstream: &mut U) -> io::Result<()>
where
    C: AsyncReadExt + AsyncWriteExt + Unpin,
    U: AsyncReadExt + AsyncWriteExt + Unpin,
{
    let mut client_buf = [0u8; 8 * 1024];
    let mut upstream_buf = [0u8; 8 * 1024];

    loop {
        tokio::select! {
            read = upstream.read(&mut upstream_buf) => {
                match read {
                    Ok(0) => {
                        let _ = client.flush().await;
                        return Ok(());
                    }
                    Ok(n) => {
                        client.write_all(&upstream_buf[..n]).await?;
                        client.flush().await?;
                    }
                    Err(e) => return Err(e),
                }
            }
            read = client.read(&mut client_buf) => {
                match read {
                    Ok(0) => {
                        loop {
                            match upstream.read(&mut upstream_buf).await {
                                Ok(0) => {
                                    let _ = client.flush().await;
                                    return Ok(());
                                }
                                Ok(n) => {
                                    client.write_all(&upstream_buf[..n]).await?;
                                    client.flush().await?;
                                }
                                Err(e) => return Err(e),
                            }
                        }
                    }
                    Ok(n) => {
                        upstream.write_all(&client_buf[..n]).await?;
                        upstream.flush().await?;
                    }
                    Err(e) => return Err(e),
                }
            }
        }
    }
}
