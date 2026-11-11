//! The TCP arm: one independent connection per channel, which is what the
//! proxy's client leg does today.

use std::net::SocketAddr;

use tokio::net::{TcpListener, TcpStream};

use crate::BoxError;

/// Serve channels until the process is killed, one task per connection.
pub async fn serve(addr: SocketAddr) -> Result<(), BoxError> {
    let listener = TcpListener::bind(addr).await?;
    eprintln!("tcp server on {}", listener.local_addr()?);
    loop {
        let (stream, _peer) = listener.accept().await?;
        // SPICE sets TCP_NODELAY on its channels; without it Nagle would add
        // its own delay to the interactive exchange and the arm would be
        // measuring Nagle rather than the transport.
        stream.set_nodelay(true)?;
        tokio::spawn(async move {
            if let Err(e) = crate::workload::serve_channel(stream).await {
                eprintln!("tcp channel ended: {e}");
            }
        });
    }
}

/// Open `channels` independent connections, each with Nagle off.
pub async fn connect(server: SocketAddr, channels: u32) -> Result<(Vec<TcpStream>, f64), BoxError> {
    let started = std::time::Instant::now();
    let mut streams = Vec::with_capacity(channels as usize);
    for _ in 0..channels {
        let stream = TcpStream::connect(server).await?;
        stream.set_nodelay(true)?;
        streams.push(stream);
    }
    Ok((streams, started.elapsed().as_secs_f64() * 1000.0))
}
