//! kerbside-proxy: an inspection-first SPICE relay.
//!
//! This is the phase-3 skeleton: it installs the rustls crypto provider,
//! parses the CLI configuration (mirroring `kerbside/config.py`), and
//! initialises tracing. Listeners, the gRPC client, the handshake, and the
//! relay are added in later steps of phase 3.

use std::path::PathBuf;

use anyhow::Result;
use clap::Parser;
use tracing::info;
use tracing_subscriber::EnvFilter;

/// Generated gRPC stubs for the KerbsideProxy control service. The client
/// type is unused in this skeleton but compiling it here proves the codegen
/// path works; later steps consume it from `src/rpc.rs`.
pub mod pb {
    #![allow(dead_code, clippy::all, clippy::pedantic)]
    tonic::include_proto!("kerbside.rpc");
}

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

    // Listeners, gRPC client, handshake, and relay are wired up in later
    // steps of phase 3. For the skeleton we log the bound config and exit 0.
    info!("kerbside-proxy skeleton: nothing to serve yet, exiting cleanly");
    Ok(())
}
