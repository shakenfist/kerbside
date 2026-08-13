//! Prometheus metrics: a global registry, typed metric handles, and a
//! minimal hyper 1.x `/metrics` HTTP server.
//!
//! A Rust-native registry (rather than a `prometheus_client` +
//! multiprocessing-queue exposition): every metric below is created once
//! (via [`std::sync::LazyLock`]) and
//! registered into a single process-wide [`Registry`], and [`serve`] gathers
//! from that registry on every `/metrics` scrape. Callers never touch the
//! registry directly -- they use the small helper functions at the bottom of
//! this module (`inc_connections`, `connection_guard`, `record_authorized`,
//! `record_denied`, `add_relayed_bytes`).

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::LazyLock;

use anyhow::{Context, Result};
use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use prometheus::{Encoder, IntCounter, IntCounterVec, IntGauge, Opts, Registry, TextEncoder};
use tokio::net::TcpListener;
use tracing::{debug, info, warn};

use crate::policy::Direction;

/// The process-wide Prometheus registry. Every metric in this module
/// registers itself here at first access; [`serve`] gathers from this
/// registry on every scrape.
static REGISTRY: LazyLock<Registry> = LazyLock::new(Registry::new);

/// Secure SPICE sessions currently being handled, from accept through
/// teardown. Held accurate on every exit path via [`ConnectionGuard`].
static ACTIVE_CONNECTIONS: LazyLock<IntGauge> = LazyLock::new(|| {
    let gauge = IntGauge::new(
        "kerbside_proxy_active_connections",
        "Secure SPICE sessions currently being relayed",
    )
    .expect("static metric name/help are valid");
    REGISTRY
        .register(Box::new(gauge.clone()))
        .expect("active_connections registers exactly once");
    gauge
});

/// Total secure SPICE connections accepted (TLS-terminated), whether or not
/// they were ultimately authorized.
static CONNECTIONS_TOTAL: LazyLock<IntCounter> = LazyLock::new(|| {
    let counter = IntCounter::new(
        "kerbside_proxy_connections_total",
        "Total secure SPICE connections accepted",
    )
    .expect("static metric name/help are valid");
    REGISTRY
        .register(Box::new(counter.clone()))
        .expect("connections_total registers exactly once");
    counter
});

/// Total connections the control service authorized (reached `Target`).
static AUTHORIZED_TOTAL: LazyLock<IntCounter> = LazyLock::new(|| {
    let counter = IntCounter::new(
        "kerbside_proxy_authorized_total",
        "Total connections authorized by the control service",
    )
    .expect("static metric name/help are valid");
    REGISTRY
        .register(Box::new(counter.clone()))
        .expect("authorized_total registers exactly once");
    counter
});

/// Total connections the control service denied.
static DENIED_TOTAL: LazyLock<IntCounter> = LazyLock::new(|| {
    let counter = IntCounter::new(
        "kerbside_proxy_denied_total",
        "Total connections denied by the control service",
    )
    .expect("static metric name/help are valid");
    REGISTRY
        .register(Box::new(counter.clone()))
        .expect("denied_total registers exactly once");
    counter
});

/// Total bytes relayed, labelled by direction
/// (`client_to_server` / `server_to_client`).
static BYTES_RELAYED_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    let vec = IntCounterVec::new(
        Opts::new(
            "kerbside_proxy_bytes_relayed_total",
            "Total bytes relayed between SPICE clients and hypervisors",
        ),
        &["direction"],
    )
    .expect("static metric options are valid");
    REGISTRY
        .register(Box::new(vec.clone()))
        .expect("bytes_relayed_total registers exactly once");
    vec
});

/// Total firewall verdicts, labelled by `channel`, `direction`, `rule`
/// (`disallowed_type` / `unmodeled_type`, extended by later L0 rules), and
/// `action` (`enforced` — the blocking verdict was applied — vs `observed` —
/// `WarnOnly` let it through, or the rule is intrinsically observe-only). The
/// enforced/observed split directly answers "what would `Enforce` have tripped?"
/// during a `WarnOnly` run.
static FIREWALL_VERDICTS_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    let vec = IntCounterVec::new(
        Opts::new(
            "kerbside_proxy_firewall_verdicts_total",
            "Total firewall verdicts by channel, direction, rule, and action",
        ),
        &["channel", "direction", "rule", "action"],
    )
    .expect("static metric options are valid");
    REGISTRY
        .register(Box::new(vec.clone()))
        .expect("firewall_verdicts_total registers exactly once");
    vec
});

/// Map a relay [`Direction`] to its Prometheus label value.
fn direction_label(dir: Direction) -> &'static str {
    match dir {
        Direction::ClientToServer => "client_to_server",
        Direction::ServerToClient => "server_to_client",
    }
}

/// Increment the count of accepted secure connections.
///
/// This does not touch `active_connections`; pair it with
/// [`connection_guard`] to track the connection's lifetime.
pub fn inc_connections() {
    CONNECTIONS_TOTAL.inc();
}

/// Record an `AuthorizeConnection` outcome of `Target` (authorized).
pub fn record_authorized() {
    AUTHORIZED_TOTAL.inc();
}

/// Record an `AuthorizeConnection` outcome of `Denied`.
pub fn record_denied() {
    DENIED_TOTAL.inc();
}

/// Add `n` bytes to the relayed-bytes counter for `dir`.
pub fn add_relayed_bytes(dir: Direction, n: u64) {
    BYTES_RELAYED_TOTAL
        .with_label_values(&[direction_label(dir)])
        .inc_by(n);
}

/// Record one firewall verdict. `rule` and `action` are the stable low-
/// cardinality labels the policy engine supplies (see [`FIREWALL_VERDICTS_TOTAL`]).
pub fn record_firewall_verdict(channel: &str, dir: Direction, rule: &str, action: &str) {
    FIREWALL_VERDICTS_TOTAL
        .with_label_values(&[channel, direction_label(dir), rule, action])
        .inc();
}

/// An RAII guard that increments `active_connections` on creation and
/// decrements it on drop.
///
/// Holding one of these for a connection's full lifetime (from accept to
/// teardown) keeps `active_connections` accurate on every exit path --
/// early return, panic-free error, or normal completion -- without needing a
/// matching manual `dec()` call at each of them.
pub struct ConnectionGuard {
    _private: (),
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        ACTIVE_CONNECTIONS.dec();
    }
}

/// Start tracking one active connection. Increments `active_connections`
/// immediately; the count is decremented automatically when the returned
/// guard is dropped.
pub fn connection_guard() -> ConnectionGuard {
    ACTIVE_CONNECTIONS.inc();
    ConnectionGuard { _private: () }
}

/// The current number of active (in-flight) connections. Used by the shutdown
/// drain to wait for sessions to finish tearing down.
pub fn active_connections() -> i64 {
    ACTIVE_CONNECTIONS.get()
}

/// Render the current registry in Prometheus text exposition format.
fn gather_text() -> Result<Vec<u8>> {
    let metric_families = REGISTRY.gather();
    let mut buffer = Vec::new();
    TextEncoder::new()
        .encode(&metric_families, &mut buffer)
        .context("encoding Prometheus metrics")?;
    Ok(buffer)
}

/// Handle one HTTP request on the metrics listener: `GET /metrics` returns
/// the Prometheus text exposition, everything else 404s. Never fails --
/// an encoding error becomes a 500 response rather than tearing down the
/// connection.
async fn handle(req: Request<Incoming>) -> std::result::Result<Response<Full<Bytes>>, Infallible> {
    if req.method() != Method::GET || req.uri().path() != "/metrics" {
        let response = Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Full::new(Bytes::new()))
            .expect("static response is valid");
        return Ok(response);
    }

    let response = match gather_text() {
        Ok(body) => Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "text/plain; version=0.0.4")
            .body(Full::new(Bytes::from(body)))
            .expect("static response is valid"),
        Err(e) => {
            warn!(error = %e, "gathering Prometheus metrics failed");
            Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Full::new(Bytes::new()))
                .expect("static response is valid")
        }
    };
    Ok(response)
}

/// Run the `/metrics` HTTP server forever, serving the process-wide registry
/// in Prometheus text exposition format.
///
/// hyper 1.x has no built-in `Server`, so this is a plain accept loop: each
/// accepted `TcpStream` is wrapped in `hyper_util`'s `TokioIo` and served as
/// one HTTP/1.1 connection via `hyper::server::conn::http1`. Every connection
/// is spawned into its own task, so a slow or hostile scraper cannot stall
/// other scrapes; per-connection I/O errors are logged and do not stop the
/// accept loop. Only a bind failure returns an error.
///
/// SECURITY: this endpoint is unauthenticated. As with the Python proxy's
/// `start_http_server` (see `kerbside/config.py`'s `PROMETHEUS_METRICS_PORT`
/// documentation), it must not be exposed to untrusted clients -- bind it
/// only where the deployment's network policy restricts scraping to trusted
/// monitoring infrastructure.
pub async fn serve(addr: SocketAddr) -> Result<()> {
    let listener = TcpListener::bind(addr)
        .await
        .with_context(|| format!("binding Prometheus metrics listener on {addr}"))?;
    info!(%addr, "Prometheus metrics listener bound");

    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(e) => {
                warn!(error = %e, "metrics listener: accept failed");
                continue;
            }
        };

        tokio::spawn(async move {
            let io = TokioIo::new(stream);
            if let Err(e) = http1::Builder::new()
                .serve_connection(io, service_fn(handle))
                .await
            {
                debug!(%peer, error = %e, "metrics connection ended with an error");
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_firewall_verdict_increments_labelled_series() {
        // Use a distinctive channel label so this series is not perturbed by
        // any other test sharing the process-wide registry.
        let series = FIREWALL_VERDICTS_TOTAL.with_label_values(&[
            "test_metric_channel",
            direction_label(Direction::ClientToServer),
            "disallowed_type",
            "enforced",
        ]);
        let before = series.get();
        record_firewall_verdict(
            "test_metric_channel",
            Direction::ClientToServer,
            "disallowed_type",
            "enforced",
        );
        assert_eq!(series.get(), before + 1);
    }
}
