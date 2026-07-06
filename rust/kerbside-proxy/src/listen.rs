//! The two SPICE listeners: plaintext (insecure, redirect-to-secure) and TLS
//! (secure, session-bearing).
//!
//! The insecure listener implements the whole of the "redirect to TLS"
//! behaviour SPICE clients rely on: read the client's link message, reply
//! `SpiceError::NeedSecured`, and close. It never proceeds to
//! authentication or relay.
//!
//! The secure listener terminates TLS and hands the resulting `SpiceStream`
//! (plus the peer address) off to a caller-supplied handler. The handshake,
//! authorization, backend connect, and relay are implemented in later steps
//! of phase 3 (3d-3f) behind that handler seam; this step only wires the
//! accept loop and a stub handler.

use std::future::Future;
use std::net::SocketAddr;
use std::time::Duration;

use anyhow::{Context, Result};
use shakenfist_spice_protocol::link::{read_link_mess, send_need_secured, SpiceStream};
use socket2::{SockRef, TcpKeepalive};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use tracing::{debug, info, warn};

/// Timeout applied to the accept-path handshake reads on both listeners
/// (the link-message read and, on the secure port, the TLS accept). The
/// crate's handshake drivers bound memory but not time, so a slow or
/// hostile peer must not be able to stall a task -- and, since `main`'s
/// concurrency-cap semaphore permit is held for the connection's whole
/// lifetime, a stuck handshake would otherwise also pin a permit --
/// indefinitely.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// TCP keepalive tuning for the accepted CLIENT socket, mirroring the backend
/// leg (the ryll `SpiceClient`, which matches spice-gtk behaviour): 30 s idle
/// before the first probe, then probes at 15 s intervals, 3 retries — so a
/// vanished peer is detected in roughly 75 s. Keepalive is the PRIMARY
/// dead-peer detector for a relayed session (the relay's idle-read timeout is
/// only a generous backstop); it closes the phase-3 deferred permit-pinning
/// finding on the client leg.
const CLIENT_KEEPALIVE_TIME: Duration = Duration::from_secs(30);
const CLIENT_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(15);
const CLIENT_KEEPALIVE_RETRIES: u32 = 3;

/// Enable TCP keepalive on an accepted client socket, mirroring the backend
/// leg. Best-effort: a keepalive-set failure is logged and NON-fatal — we do
/// not drop an otherwise healthy connection over it. Called before the TLS
/// accept so the probes cover the whole session.
fn set_client_keepalive(stream: &TcpStream, peer: SocketAddr) {
    let keepalive = TcpKeepalive::new()
        .with_time(CLIENT_KEEPALIVE_TIME)
        .with_interval(CLIENT_KEEPALIVE_INTERVAL)
        .with_retries(CLIENT_KEEPALIVE_RETRIES);
    let sock = SockRef::from(stream);
    if let Err(e) = sock.set_keepalive(true) {
        warn!(%peer, error = %e, "enabling client TCP keepalive failed; continuing");
        return;
    }
    if let Err(e) = sock.set_tcp_keepalive(&keepalive) {
        warn!(%peer, error = %e, "setting client TCP keepalive parameters failed; continuing");
    }
}

/// Run the insecure (plaintext) SPICE listener forever.
///
/// Per accepted connection: set `TCP_NODELAY`, read the client's link
/// message, reply with a `NeedSecured` error redirect, and close. This is
/// the complete behaviour of the insecure port -- no authentication or
/// relay ever happens over plaintext. Each connection runs in its own
/// spawned task, so a slow or hostile client cannot stall other clients;
/// handshake errors and timeouts are logged at debug and simply drop the
/// connection rather than killing the loop. Only a bind failure returns an
/// error.
pub async fn run_insecure(addr: SocketAddr) -> Result<()> {
    let listener = TcpListener::bind(addr)
        .await
        .with_context(|| format!("binding insecure SPICE listener on {addr}"))?;
    info!(%addr, "insecure SPICE listener bound");

    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(e) => {
                warn!(error = %e, "insecure listener: accept failed");
                continue;
            }
        };

        tokio::spawn(async move {
            match handle_insecure(stream).await {
                Ok(()) => debug!(%peer, "insecure connection: redirected to secure port"),
                Err(e) => {
                    debug!(%peer, error = %e, "insecure connection: handshake failed or timed out")
                }
            }
        });
    }
}

async fn handle_insecure(mut stream: TcpStream) -> Result<()> {
    stream.set_nodelay(true).context("setting TCP_NODELAY")?;

    tokio::time::timeout(HANDSHAKE_TIMEOUT, async {
        read_link_mess(&mut stream).await?;
        send_need_secured(&mut stream).await
    })
    .await
    .context("insecure handshake timed out")??;

    Ok(())
}

/// Run the secure (TLS) SPICE listener forever.
///
/// Per accepted connection: set `TCP_NODELAY`, complete the TLS accept
/// (under the same handshake timeout as the insecure listener), then call
/// `handler(SpiceStream::TlsServer(tls_stream), peer)` in its own spawned
/// task.
///
/// `handler` is the seam later steps (3d-3f) fill with the real
/// session: the link handshake, authorization, backend connect, and
/// inspection-first relay. It is `Fn(SpiceStream, SocketAddr) -> Fut`
/// rather than a trait object so it can be a plain (often capture-free)
/// closure or a cheap `Clone` handle (e.g. wrapping an `Arc` of shared
/// state such as the gRPC client); `run_secure` clones it once per accepted
/// connection so each spawned task owns its own handle. Errors and TLS
/// accept timeouts are logged at debug and drop the connection; only a bind
/// failure returns an error.
pub async fn run_secure<F, Fut>(addr: SocketAddr, acceptor: TlsAcceptor, handler: F) -> Result<()>
where
    F: Fn(SpiceStream, SocketAddr) -> Fut + Clone + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let listener = TcpListener::bind(addr)
        .await
        .with_context(|| format!("binding secure SPICE listener on {addr}"))?;
    info!(%addr, "secure SPICE listener bound");

    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(e) => {
                warn!(error = %e, "secure listener: accept failed");
                continue;
            }
        };

        let acceptor = acceptor.clone();
        let handler = handler.clone();

        tokio::spawn(async move {
            match accept_tls(&acceptor, stream, peer).await {
                Ok(tls_stream) => {
                    debug!(%peer, "secure connection: TLS accepted");
                    handler(SpiceStream::TlsServer(tls_stream), peer).await;
                }
                Err(e) => {
                    debug!(%peer, error = %e, "secure connection: TLS accept failed or timed out")
                }
            }
        });
    }
}

async fn accept_tls(
    acceptor: &TlsAcceptor,
    stream: TcpStream,
    peer: SocketAddr,
) -> Result<tokio_rustls::server::TlsStream<TcpStream>> {
    stream.set_nodelay(true).context("setting TCP_NODELAY")?;
    // Enable keepalive on the client leg before TLS so a silent/vanished client
    // is detected and cannot pin a concurrency permit (mirrors the backend leg).
    set_client_keepalive(&stream, peer);

    let tls_stream = tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(stream))
        .await
        .context("TLS accept timed out")??;

    Ok(tls_stream)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Smoke test: enabling keepalive on a real loopback socket must not error
    /// (the call is best-effort, so this only proves the wiring works on the
    /// common platform, not that the params were rejected elsewhere).
    #[tokio::test]
    async fn set_client_keepalive_on_loopback_succeeds() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("binding a loopback listener");
        let addr = listener.local_addr().expect("local_addr");
        let connect = tokio::spawn(async move { TcpStream::connect(addr).await });
        let (server, peer) = listener.accept().await.expect("accept");
        let _client = connect.await.expect("connect task").expect("connect");

        // Directly assert the socket2 calls succeed here (the production helper
        // swallows errors as non-fatal); this catches a platform/param regression.
        let keepalive = TcpKeepalive::new()
            .with_time(CLIENT_KEEPALIVE_TIME)
            .with_interval(CLIENT_KEEPALIVE_INTERVAL)
            .with_retries(CLIENT_KEEPALIVE_RETRIES);
        let sock = SockRef::from(&server);
        sock.set_keepalive(true).expect("set_keepalive");
        sock.set_tcp_keepalive(&keepalive)
            .expect("set_tcp_keepalive");

        // And the production helper must not panic.
        set_client_keepalive(&server, peer);
    }
}
