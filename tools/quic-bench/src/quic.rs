//! The QUIC arm: one connection carrying one bidirectional stream per channel.

use std::fs::File;
use std::io::BufReader;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use quinn::congestion::{BbrConfig, CubicConfig, NewRenoConfig};
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn::{
    ClientConfig, Endpoint, EndpointConfig, Runtime, ServerConfig, TokioRuntime, TransportConfig,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

use crate::nogso::NoGso;
use crate::{BoxError, Cc};

/// Application protocol name. Ours, unregistered, and only ever seen by this
/// bench's own two processes.
const ALPN: &[u8] = b"quic-bench/1";

/// The name the client asks for and the certificate carries.
pub const SERVER_NAME: &str = "quic-bench";

/// Flow control large enough that it is never the bottleneck. The widest
/// bandwidth-delay product measured here is 10 Mbit at 80 ms, about 100 kB,
/// and the netem queue adds one more of those; megabytes of window keep the
/// comparison about congestion control rather than about receive buffers.
const RECEIVE_WINDOW: u32 = 16 * 1024 * 1024;
const STREAM_RECEIVE_WINDOW: u32 = 8 * 1024 * 1024;
const SEND_WINDOW: u64 = 16 * 1024 * 1024;

/// Datagram size, pinned with path MTU discovery switched off.
///
/// Two reasons to pin it. It makes the netem queue's bytes-per-slot a single
/// expected number, which is how the GSO check is read; and it stops MTU
/// probing from adding its own loss events to a run that is measuring loss.
/// 1400 bytes of UDP payload is 1442 bytes on an Ethernet link, which is the
/// figure the queue is checked against.
pub const PINNED_MTU: u16 = 1400;

/// Send priority given to the interactive stream when the sensitivity arm asks
/// for it. quinn serves higher-priority send streams first; every stream is 0
/// by default, which is what the headline arm leaves them at, because a
/// straightforward integration would not think to change it.
const INTERACTIVE_PRIORITY: i32 = 8;

fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>, BoxError> {
    let mut reader = BufReader::new(File::open(path)?);
    let certs = rustls_pemfile::certs(&mut reader).collect::<Result<Vec<_>, _>>()?;
    if certs.is_empty() {
        return Err(format!("no certificates in {}", path.display()).into());
    }
    Ok(certs)
}

fn load_key(path: &Path) -> Result<PrivateKeyDer<'static>, BoxError> {
    let mut reader = BufReader::new(File::open(path)?);
    rustls_pemfile::private_key(&mut reader)?
        .ok_or_else(|| format!("no private key in {}", path.display()).into())
}

/// Transport configuration shared by both ends, so the two directions use the
/// same congestion controller and the same datagram size.
fn transport_config(cc: Cc, channels: u32) -> TransportConfig {
    let mut config = TransportConfig::default();
    match cc {
        Cc::Cubic => {
            config.congestion_controller_factory(Arc::new(CubicConfig::default()));
        }
        Cc::Bbr => {
            config.congestion_controller_factory(Arc::new(BbrConfig::default()));
        }
        Cc::Reno => {
            config.congestion_controller_factory(Arc::new(NewRenoConfig::default()));
        }
    }
    config
        .initial_mtu(PINNED_MTU)
        .mtu_discovery_config(None)
        .max_concurrent_bidi_streams((channels + 8).into())
        .receive_window(RECEIVE_WINDOW.into())
        .stream_receive_window(STREAM_RECEIVE_WINDOW.into())
        .send_window(SEND_WINDOW)
        .max_idle_timeout(Some(
            Duration::from_secs(60)
                .try_into()
                .expect("60s is a valid idle timeout"),
        ))
        .keep_alive_interval(None);
    config
}

/// Build an endpoint. With `allow_gso` false -- which is what every measured
/// run uses -- the runtime's socket is wrapped so quinn never batches
/// datagrams. `allow_gso` true exists only as the positive control for the
/// queue-accounting check: it is the knowingly wrong configuration, and a run
/// made with it is a diagnostic, not a result.
///
/// Returns the endpoint, the number of transmit segments the underlying socket
/// offered, and the number actually in use.
fn endpoint(
    addr: SocketAddr,
    server_config: Option<ServerConfig>,
    allow_gso: bool,
) -> Result<(Endpoint, usize, usize), BoxError> {
    let socket = std::net::UdpSocket::bind(addr)?;
    let runtime: Arc<dyn Runtime> = Arc::new(TokioRuntime);
    let wrapped = runtime.wrap_udp_socket(socket)?;
    let available = wrapped.max_transmit_segments();
    let socket: Arc<dyn quinn::AsyncUdpSocket> = if allow_gso {
        wrapped
    } else {
        Arc::new(NoGso::new(wrapped))
    };
    let used = socket.max_transmit_segments();
    let endpoint = Endpoint::new_with_abstract_socket(
        EndpointConfig::default(),
        server_config,
        socket,
        runtime,
    )?;
    Ok((endpoint, available, used))
}

/// Serve channels until the process is killed. Each accepted bidirectional
/// stream is one channel, joined into a single duplex value so the workload
/// code cannot tell it from a TCP connection.
pub async fn serve(
    addr: SocketAddr,
    cert: &Path,
    key: &Path,
    cc: Cc,
    channels: u32,
    allow_gso: bool,
    priority_interactive: bool,
) -> Result<(), BoxError> {
    let mut crypto =
        rustls::ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_no_client_auth()
            .with_single_cert(load_certs(cert)?, load_key(key)?)?;
    crypto.alpn_protocols = vec![ALPN.to_vec()];
    let mut server_config =
        ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(crypto)?));
    server_config.transport_config(Arc::new(transport_config(cc, channels)));

    let (endpoint, available, used) = endpoint(addr, Some(server_config), allow_gso)?;
    eprintln!(
        "quic server on {} cc={cc} mtu={PINNED_MTU} gso_segments_available={available} gso_segments_used={used}",
        endpoint.local_addr()?
    );

    while let Some(incoming) = endpoint.accept().await {
        tokio::spawn(async move {
            let connection = match incoming.await {
                Ok(connection) => connection,
                Err(e) => {
                    eprintln!("quic handshake failed: {e}");
                    return;
                }
            };
            loop {
                match connection.accept_bi().await {
                    Ok((send, mut recv)) => {
                        tokio::spawn(async move {
                            // The header is read here rather than inside the
                            // workload so the role is known while the send
                            // half is still separate: setting a priority needs
                            // both.
                            let (role, size) = match crate::workload::read_header(&mut recv).await {
                                Ok(header) => header,
                                Err(e) => {
                                    eprintln!("quic channel header: {e}");
                                    return;
                                }
                            };
                            if priority_interactive && role == crate::workload::ROLE_INTERACTIVE {
                                let _ = send.set_priority(INTERACTIVE_PRIORITY);
                            }
                            let stream = tokio::io::join(recv, send);
                            if let Err(e) = crate::workload::serve_role(stream, role, size).await {
                                eprintln!("quic channel ended: {e}");
                            }
                        });
                    }
                    Err(e) => {
                        eprintln!("quic connection ended: {e}");
                        return;
                    }
                }
            }
        });
    }
    Ok(())
}

/// Open one bidirectional stream per channel, giving the interactive one a
/// send priority if the sensitivity arm asked for it.
///
/// A quinn stream does not exist on the wire until something is written to it,
/// so the server sees each one only when the workload writes its header, which
/// it does immediately.
pub async fn open_channels(
    connection: &quinn::Connection,
    channels: u32,
    priority_interactive: bool,
) -> Result<Vec<tokio::io::Join<quinn::RecvStream, quinn::SendStream>>, BoxError> {
    let mut streams = Vec::with_capacity(channels as usize);
    for index in 0..channels as usize {
        let (send, recv) = connection.open_bi().await?;
        if priority_interactive
            && crate::workload::role_for(index) == crate::workload::ROLE_INTERACTIVE
        {
            send.set_priority(INTERACTIVE_PRIORITY)?;
        }
        streams.push(tokio::io::join(recv, send));
    }
    Ok(streams)
}

/// What the client learned about its own transport, for the results file.
pub struct ConnectionFacts {
    pub connect_ms: f64,
    pub gso_segments_available: usize,
    pub gso_segments_used: usize,
}

/// One connection, `channels` bidirectional streams. A quinn stream does not
/// exist on the wire until something is written to it, so the server sees each
/// one only when the workload writes its header -- which it does immediately.
pub async fn connect(
    server: SocketAddr,
    cert: &Path,
    cc: Cc,
    channels: u32,
    allow_gso: bool,
) -> Result<(Endpoint, quinn::Connection, ConnectionFacts), BoxError> {
    let mut roots = rustls::RootCertStore::empty();
    for certificate in load_certs(cert)? {
        roots.add(certificate)?;
    }
    let mut crypto =
        rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_root_certificates(roots)
            .with_no_client_auth();
    crypto.alpn_protocols = vec![ALPN.to_vec()];
    let mut client_config = ClientConfig::new(Arc::new(QuicClientConfig::try_from(crypto)?));
    client_config.transport_config(Arc::new(transport_config(cc, channels)));

    let bind: SocketAddr = if server.is_ipv4() {
        "0.0.0.0:0".parse()?
    } else {
        "[::]:0".parse()?
    };
    let (endpoint, gso_segments_available, gso_segments_used) = endpoint(bind, None, allow_gso)?;

    let started = std::time::Instant::now();
    let connection = endpoint
        .connect_with(client_config, server, SERVER_NAME)?
        .await?;
    let connect_ms = started.elapsed().as_secs_f64() * 1000.0;

    // The endpoint owns the socket, so the caller has to keep it alive for as
    // long as it uses the connection.
    Ok((
        endpoint,
        connection,
        ConnectionFacts {
            connect_ms,
            gso_segments_available,
            gso_segments_used,
        },
    ))
}
