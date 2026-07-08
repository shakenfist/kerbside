//! kerbside-proxy: an inspection-first SPICE relay.
//!
//! This is the phase-3 proxy: it installs the rustls crypto provider, parses
//! the CLI configuration (mirroring `kerbside/config.py`), and initialises
//! tracing, then stands up the full connection path -- the plaintext
//! (redirect-to-secure) and TLS SPICE listeners, the gRPC client to the
//! `KerbsideProxy` control service, the per-connection handshake +
//! authorization, the backend hypervisor connect, and the inspection-first
//! relay -- behind a concurrency cap, with a Prometheus `/metrics` endpoint
//! and graceful shutdown on SIGTERM/Ctrl-C. Firewall enforcement (L0/L1) is
//! phase 4; daemon integration and session-termination push are phase 5.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use shakenfist_spice_protocol::link::SpiceStream;
use tokio::sync::Semaphore;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

/// Generated gRPC stubs for the KerbsideProxy control service.
pub mod pb {
    #![allow(dead_code, clippy::all, clippy::pedantic)]
    tonic::include_proto!("kerbside.rpc");
}

/// gRPC client for the KerbsideProxy control service over the UDS.
mod rpc;

/// The plaintext (insecure, redirect-to-secure) and TLS (secure) SPICE
/// listeners.
mod listen;

/// TLS acceptor construction (cert/key loading) for the secure listener.
mod tls;

/// The per-connection client-facing handshake + authorization.
mod session;

/// The backend leg: hypervisor connect (with the need_secured retry) + relay
/// handoff.
mod backend;

/// The relay's inspection policy seam (Policy/Verdict/Direction). Phase 3
/// ships PermissivePolicy; phase 4 fills it with L0/L1 enforcement.
mod policy;

/// The compiled-in L1 message-type grammar table (per channel + direction).
/// Consulted by phase 4's firewall engine (`policy.rs`).
mod allowlist;

/// The inspection-first, per-message-framed SPICE relay.
mod relay;

/// The global Prometheus registry, metric helpers, and the `/metrics` hyper
/// server.
mod metrics;

/// A coarse cap on concurrently-handled secure connections, enforced by a
/// `tokio::sync::Semaphore` in `main`'s secure-connection handler. This is a
/// blunt process-wide limit to bound resource use under load; phases 4/5 may
/// make it configurable (a CLI flag) or replace it with finer-grained
/// backpressure.
const MAX_CONCURRENT_SESSIONS: usize = 1000;

/// Kerbside SPICE proxy configuration. Defaults mirror `kerbside/config.py`
/// so the Python daemon can pass matching values when it spawns the proxy
/// (phase 5).
#[derive(Debug, Parser)]
#[command(name = "kerbside-proxy", about = "Kerbside SPICE proxy")]
struct Args {
    /// IPv4 address to bind the SPICE proxy listeners to.
    #[arg(long, default_value = "0.0.0.0")]
    vdi_address: String,

    /// Port to bind for secure (TLS) SPICE connections.
    #[arg(long, default_value_t = 5900)]
    secure_port: u16,

    /// Port to bind for insecure (redirect-to-secure) SPICE connections.
    #[arg(long, default_value_t = 5901)]
    insecure_port: u16,

    /// TLS host certificate for the proxy.
    #[arg(long, default_value = "/etc/pki/CA/certs/proxy.pem")]
    cert: PathBuf,

    /// Key for the proxy's TLS host certificate.
    #[arg(long, default_value = "/etc/pki/CA/certs/proxy-key.pem")]
    cert_key: PathBuf,

    /// CA certificate used to verify hypervisor SPICE servers.
    #[arg(long, default_value = "/etc/pki/CA/ca-cert.pem")]
    cacert: PathBuf,

    /// TLS host subject matching the one set for VDI proxies.
    #[arg(long, default_value = "C=US,O=Shaken Fist,CN=Kerbside Proxy")]
    host_subject: String,

    /// This proxy node's name, used for channel bookkeeping.
    #[arg(long, default_value = "kerbside")]
    node_name: String,

    /// Port to expose Prometheus metrics on.
    #[arg(long, default_value_t = 13003)]
    prometheus_port: u16,

    /// Address to bind the Prometheus /metrics server to. Defaults to
    /// loopback: the endpoint is unauthenticated, so it must not be exposed on
    /// the public VDI interface. Set to a management address (or 0.0.0.0
    /// behind a firewall) to scrape from another host.
    #[arg(long, default_value = "127.0.0.1")]
    metrics_address: String,

    /// Unix domain socket path for the KerbsideProxy gRPC service.
    #[arg(long, default_value = "/run/kerbside/api.sock")]
    api_socket: PathBuf,

    /// Enable debug-level logging.
    #[arg(long)]
    verbose: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    // The ryll SpiceClient (and any rustls TLS) requires a process-default
    // crypto provider; install ring once at startup. Idempotent via `let _`.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let args = Args::parse();

    // Default to info, or debug when --verbose, unless RUST_LOG overrides.
    let default_level = if args.verbose { "debug" } else { "info" };
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default_level));
    tracing_subscriber::fmt().with_env_filter(filter).init();

    info!(
        node_name = %args.node_name,
        vdi_address = %args.vdi_address,
        secure_port = args.secure_port,
        insecure_port = args.insecure_port,
        prometheus_port = args.prometheus_port,
        api_socket = %args.api_socket.display(),
        cert = %args.cert.display(),
        cert_key = %args.cert_key.display(),
        cacert = %args.cacert.display(),
        host_subject = %args.host_subject,
        "kerbside-proxy starting"
    );

    // gRPC client for the control service over the UDS. The channel is lazy,
    // so this is infallible and only dials the socket on first use.
    let rpc = rpc::KerbsideRpc::connect(&args.api_socket);

    // Shared, cheaply-cloneable state cloned into each connection task.
    let state = Arc::new(session::SharedState {
        rpc,
        node_name: args.node_name.clone(),
        sessions: Arc::new(session::SessionRegistry::default()),
    });

    // Drop any stale channel rows this node left behind (e.g. from a crash or
    // an unclean restart) before accepting new connections, via the
    // ClearNodeChannels RPC. A failure here means
    // the control service (or its socket) is not reachable yet; that is not
    // fatal to starting up -- the per-connection RPCs below will surface the
    // same problem loudly and repeatedly if it persists.
    if let Err(e) = state.rpc.clear_node_channels(&args.node_name).await {
        warn!(
            node_name = %args.node_name,
            error = %e,
            "ClearNodeChannels at startup failed; continuing"
        );
    }

    // Consume the ProxyControl event stream in the background: heartbeats are
    // logged, TerminateSession cancels the session's in-flight channels via the
    // shared registry. A failure to even open the stream (e.g. the daemon is
    // not up yet) is logged and the task simply ends; it is not reconnected
    // this phase.
    {
        let state = state.clone();
        tokio::spawn(async move {
            let sessions = state.sessions.clone();
            if let Err(e) = state
                .rpc
                .run_proxy_control(state.node_name.clone(), sessions)
                .await
            {
                warn!(error = %e, "ProxyControl consumer task ended with an error");
            }
        });
    }

    // Kept for the graceful-drain step on shutdown (below); cloned before the
    // secure handler moves `state`.
    let drain_sessions = state.sessions.clone();

    let acceptor = tls::load_acceptor(&args.cert, &args.cert_key).with_context(|| {
        format!(
            "loading TLS cert {} / key {} for the secure SPICE listener",
            args.cert.display(),
            args.cert_key.display()
        )
    })?;

    let vdi_ip: std::net::IpAddr = args
        .vdi_address
        .parse()
        .with_context(|| format!("parsing --vdi-address {}", args.vdi_address))?;
    let secure_addr = SocketAddr::new(vdi_ip, args.secure_port);
    let insecure_addr = SocketAddr::new(vdi_ip, args.insecure_port);
    // The /metrics endpoint is unauthenticated, so it binds its OWN address
    // (--metrics-address, loopback by default) rather than the public VDI
    // interface -- do not expose it to untrusted networks (see config.py's
    // PROMETHEUS_METRICS_ADDRESS / PROMETHEUS_METRICS_PORT documentation).
    let metrics_ip: std::net::IpAddr = args
        .metrics_address
        .parse()
        .with_context(|| format!("parsing --metrics-address {}", args.metrics_address))?;
    let metrics_addr = SocketAddr::new(metrics_ip, args.prometheus_port);

    // Coarse cap on concurrently-handled secure connections. A permit is
    // acquired before a session runs and held for its whole lifetime; when
    // the cap is reached, new connections simply wait for a permit
    // (backpressure) rather than being rejected.
    let semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_SESSIONS));

    // Per accepted (TLS-terminated) connection, run the client-facing
    // handshake + authorization (and, on success, the backend handoff).
    // `run_secure` clones this handler per connection, so each spawned task
    // owns its own `Arc` clone of the shared state and the semaphore.
    let secure_handler = move |stream: SpiceStream, peer: SocketAddr| {
        let state = state.clone();
        let semaphore = semaphore.clone();
        async move {
            // Never closed, so acquiring a permit only fails if the
            // semaphore itself is dropped -- which it isn't while `main` is
            // running.
            let _permit = semaphore
                .acquire_owned()
                .await
                .expect("concurrency-cap semaphore is never closed");
            session::handle_connection(state, stream, peer).await;
        }
    };

    tokio::select! {
        res = listen::run_insecure(insecure_addr) => {
            res.context("insecure SPICE listener failed")?;
        }
        res = listen::run_secure(secure_addr, acceptor, secure_handler) => {
            res.context("secure SPICE listener failed")?;
        }
        res = metrics::serve(metrics_addr) => {
            res.context("Prometheus metrics server failed")?;
        }
        () = shutdown_signal() => {
            // The `select!` returning here stops the accept loops (no new
            // connections). Terminate in-flight sessions so their relays tear
            // down cleanly (close sockets, flush audit) rather than being
            // abruptly dropped when the runtime stops, then wait for the active
            // count to reach zero within a deadline. Pairs with the daemon
            // supervisor's SIGTERM-then-SIGKILL (its deadline is longer).
            let active = metrics::active_connections();
            info!(
                active,
                drain_timeout_secs = DRAIN_TIMEOUT.as_secs(),
                "shutdown signal received; draining in-flight sessions"
            );
            drain_sessions.terminate_all();
            drain_in_flight(DRAIN_TIMEOUT).await;
        }
    }

    Ok(())
}

/// Deadline for the graceful drain on shutdown: how long to wait for in-flight
/// sessions to tear down before returning (after which the runtime drops any
/// stragglers). Sized below the daemon supervisor's SIGTERM-then-SIGKILL
/// window so the proxy exits cleanly first.
const DRAIN_TIMEOUT: Duration = Duration::from_secs(10);

/// Poll the active-connection gauge until it reaches zero or `deadline`
/// elapses, so a clean shutdown waits for terminated sessions to finish
/// tearing down instead of dropping them mid-relay.
async fn drain_in_flight(deadline: Duration) {
    let start = tokio::time::Instant::now();
    loop {
        let active = metrics::active_connections();
        if active <= 0 {
            info!("all in-flight sessions drained");
            return;
        }
        if start.elapsed() >= deadline {
            warn!(
                active,
                "drain deadline reached; exiting with sessions still in flight"
            );
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Resolve once either Ctrl-C or SIGTERM is received.
///
/// `tokio::select!` in `main` races this against the listeners and the
/// metrics server; whichever finishes first cancels (drops) the others, so a
/// signal here cleanly unwinds the accept loops instead of the process being
/// killed out from under them.
async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut stream) => {
                stream.recv().await;
            }
            Err(e) => {
                warn!(error = %e, "failed to install SIGTERM handler");
                // Fall back to only Ctrl-C rather than returning immediately
                // (which would make `select!` treat "can't install SIGTERM"
                // the same as "SIGTERM received").
                std::future::pending::<()>().await;
            }
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {},
        () = terminate => {},
    }
}
