//! The backend leg + relay handoff.
//!
//! `run` receives the authorized client `SpiceStream` and everything needed to
//! open the matching hypervisor channel, then hands off to the inspection-first
//! relay:
//!
//! - `state` for the gRPC client (audit events) and node name,
//! - `connection_ref` for bookkeeping/audit correlation,
//! - `client_stream`, the TLS-terminated, authorized client stream to relay,
//! - the SPICE channel identity (`connection_id`, `channel_type`,
//!   `channel_id`) to replay onto the backend link handshake,
//! - `client_caps`, the capabilities the client advertised, forwarded to
//!   the backend so spice-server encodes for the real client (see
//!   `crate::caps`), and
//! - `target`, the authorized upstream descriptor (hypervisor host/ip, secure
//!   / insecure ports, ticket, CA cert, host subject) to build a
//!   `ConnectionConfig` from.
//!
//! It builds the `ConnectionConfig` from `target`, connects via `SpiceClient`,
//! emits the hypervisor connect success/failure audit events, and then hands
//! the two streams to the relay (`crate::relay::run`). In a build with the
//! `transcode` feature, run with `--transcode-display`, a session's first
//! display channel goes to the transcoding display channel
//! (`crate::transcode::run`) instead, dialled with the capabilities that
//! describe ryll's renderer rather than the client's. Run with the hidden
//! `--transcode-switch-after-secs`, that display channel moves between the
//! two while it runs (`crate::transcode::switch`), dialling the backend
//! afresh for each.
//!
//! A direct target is dialled insecure first, with a `need_secured` retry over
//! TLS (which the crate does not perform itself). A tunnelled target
//! (`target.tunnel` set) is dialled once, over TLS only, through its HTTP
//! CONNECT proxy.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Error, Result};
use shakenfist_spice_protocol::link::{SpiceLinkReply, SpiceStream};
use shakenfist_spice_protocol::proxy::parse_proxy_uri;
use shakenfist_spice_protocol::{ChannelType, ConnectionConfig, SpiceClient};
use socket2::SockRef;
use tokio::net::TcpStream;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::caps::{self, ClientCaps};
use crate::pb;
use crate::policy::FirewallPolicy;
use crate::session::SharedState;

/// Upper bound on a single backend connect attempt (TCP connect + SPICE link +
/// auth handshake). Without this, a hypervisor that accepts TCP but stalls the
/// SPICE handshake would pin the connection's concurrency permit indefinitely
/// (the session `HANDSHAKE_TIMEOUT` deliberately covers only the client leg,
/// and the crate's `connect_channel` has no timeout of its own). Applied per
/// attempt, so the insecure-then-secure retry gets a fresh budget each time.
const BACKEND_CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// Detect the crate's "server requires TLS" (`NeedSecured`) error.
///
/// FRAGILE: this is a string match over the error chain, forced by the ryll
/// crate not exposing a typed `NeedSecured` error --
/// `SpiceClient::connect_channel_with_caps` maps `SpiceError::NeedSecured` to
/// `anyhow!("Server requires TLS connection. Use tls-port in config.")`, so we
/// have nothing to match on but the message.
/// Any other connect failure (refused, TLS handshake, bad ticket, ...) must NOT
/// match here, so we deliberately look only for the distinctive substrings.
///
/// Future work: add a typed `NeedSecured` error (or a dedicated error kind) to
/// the ryll `shakenfist-spice-protocol` crate and match on that instead.
fn is_need_secured(err: &Error) -> bool {
    err.chain().any(|cause| {
        let msg = cause.to_string().to_lowercase();
        msg.contains("requires tls") || msg.contains("secured")
    })
}

/// Connect to the hypervisor, emit the connect audit events, and hand both
/// streams to the relay.
///
/// A tunnelled target gets exactly one TLS attempt through its proxy; a direct
/// one gets the proxy-side `need_secured` retry the crate lacks (see
/// `connect_direct`). Returns `Err` if the backend connection cannot be
/// established (after any retry); the caller closes the client connection and
/// deregisters the channel.
#[allow(clippy::too_many_arguments)]
pub async fn run(
    state: &SharedState,
    policy: Arc<FirewallPolicy>,
    connection_ref: &str,
    client_stream: SpiceStream,
    connection_id: u32,
    channel_type: ChannelType,
    channel_id: u8,
    client_caps: &ClientCaps,
    target: &pb::Target,
    cancel: CancellationToken,
) -> Result<()> {
    // A display channel that moves between relaying and transcoding while it
    // runs dials the backend once for each mode, so it takes over here.
    #[cfg(feature = "transcode")]
    if let Some((options, every)) =
        crate::transcode::switching(state, channel_type, channel_id, connection_ref)
    {
        let link = BackendLink {
            connection_id,
            channel_type,
            channel_id,
            common_caps: caps::backend_common_caps(&client_caps.common),
            channel_caps: crate::transcode::BACKEND_DISPLAY_CAPS.to_vec(),
        };
        return crate::transcode::switch::run(
            state,
            policy,
            client_stream,
            client_caps,
            connection_ref,
            target,
            cancel,
            &options,
            every,
            || dial(state, connection_ref, target, &link, false),
        )
        .await;
    }

    // A transcoded display channel is read by ryll's renderer, not the
    // client, so it is dialled with the renderer's capabilities instead of
    // the client's (see `crate::transcode::BACKEND_DISPLAY_CAPS`).
    #[cfg(feature = "transcode")]
    let transcode = crate::transcode::choose(state, channel_type, channel_id, connection_ref);
    #[cfg(feature = "transcode")]
    let channel_caps = if transcode.is_some() {
        debug!(
            %connection_ref,
            backend_channel_caps = ?crate::transcode::BACKEND_DISPLAY_CAPS,
            "transcoding this display channel; dialling the backend with the renderer's caps"
        );
        crate::transcode::BACKEND_DISPLAY_CAPS.to_vec()
    } else {
        client_caps.channel.clone()
    };
    #[cfg(not(feature = "transcode"))]
    let channel_caps = client_caps.channel.clone();
    let link = BackendLink {
        connection_id,
        channel_type,
        channel_id,
        common_caps: caps::backend_common_caps(&client_caps.common),
        channel_caps,
    };

    // The caps Kerbside offered the client say nothing about a transcoded
    // backend leg, so the mismatch warning is for relayed channels only.
    #[cfg(feature = "transcode")]
    let relayed = transcode.is_none();
    #[cfg(not(feature = "transcode"))]
    let relayed = true;
    let backend_stream = dial(state, connection_ref, target, &link, relayed).await?;

    #[cfg(feature = "transcode")]
    if let Some(options) = transcode {
        return crate::transcode::run(
            state,
            policy,
            client_stream,
            backend_stream,
            client_caps,
            connection_ref,
            target,
            cancel,
            &options,
        )
        .await;
    }

    // Hand both owned streams to the relay seam, along with the connection's
    // firewall policy and the state/target the relay needs to flush a single
    // coalesced firewall-verdict audit event on teardown.
    crate::relay::run(
        state,
        policy,
        client_stream,
        backend_stream,
        channel_type,
        connection_ref,
        target,
        cancel,
    )
    .await
}

/// Open the backend channel `link` describes on the hypervisor `target`
/// names: a direct target insecure first, then over TLS if the hypervisor
/// asks for it; a tunnelled one once, over TLS, through its proxy. Caps
/// the socket's receive buffer, logs the capabilities the backend granted
/// (warning, if `relayed`, about any the client was offered and the backend
/// lacks), and records the connect's success or failure as an audit event.
///
/// Returns `Err` if the backend connection cannot be established (after any
/// retry).
async fn dial(
    state: &SharedState,
    connection_ref: &str,
    target: &pb::Target,
    link: &BackendLink,
    relayed: bool,
) -> Result<SpiceStream> {
    let channel_type = link.channel_type;
    // An unusable target is a failed connect like any other, so it reaches
    // the audit trail rather than only the proxy's log.
    let connected = match build_config(target) {
        // A tunnel is TLS only: build_config has already set tls_port, and
        // there is no insecure attempt to escalate from.
        Ok(config) if target.tunnel.is_some() => connect_once(&config, link).await,
        Ok(config) => connect_direct(config, link, connection_ref, target).await,
        Err(e) => Err(e),
    };
    let (backend_stream, backend_reply) = match connected {
        Ok(connected) => connected,
        Err(e) => {
            record_connect_failure(state, connection_ref, channel_type, target, &e).await;
            return Err(e);
        }
    };

    // Cap the backend-leg receive buffer before any display traffic is
    // relayed, so the backlog we hold on spice-server's behalf stays small.
    set_backend_rcvbuf(&backend_stream, state.backend_rcvbuf_bytes, connection_ref);

    if relayed {
        log_backend_caps(connection_ref, channel_type, link, &backend_reply);
    } else {
        debug!(
            %connection_ref,
            backend_common_caps = ?backend_reply.common_caps,
            backend_channel_caps = ?backend_reply.channel_caps,
            "transcoded backend link capabilities"
        );
    }

    // Successful hypervisor connection: record the audit event. The ticket is
    // never logged. Audit RPC failures are non-fatal -- log and continue
    // rather than tearing down a live connection.
    if let Err(e) = state
        .rpc
        .record_audit_event(
            &target.source,
            &target.uuid,
            &target.session_id,
            channel_type.name(),
            &state.node_name,
            connection_ref,
            "Hypervisor connection successful",
        )
        .await
    {
        warn!(%connection_ref, error = %e, "recording hypervisor-connect-success audit event failed");
    }

    info!(
        %connection_ref,
        hypervisor = %target.hypervisor,
        hypervisor_ip = %target.hypervisor_ip,
        tunnelled = target.tunnel.is_some(),
        session_id = %target.session_id,
        channel_type = channel_type.name(),
        channel_id = link.channel_id,
        connection_id = link.connection_id,
        "hypervisor connection successful; handing off to relay"
    );
    Ok(backend_stream)
}

/// Connect to a direct (untunnelled) target insecure first, retrying over TLS
/// only when the server answers `NEED_SECURED` and there is a secure port to
/// try. Any other failure on the first attempt is returned as-is (no retry).
async fn connect_direct(
    base_config: ConnectionConfig,
    link: &BackendLink,
    connection_ref: &str,
    target: &pb::Target,
) -> Result<(SpiceStream, SpiceLinkReply)> {
    let first_err = match connect_once(&base_config, link).await {
        Ok(connected) => return Ok(connected),
        Err(e) => e,
    };
    if !is_need_secured(&first_err) || target.secure_port == 0 {
        return Err(first_err);
    }

    // CI-ORACLE: the message text and the host_subject field are
    // load-bearing for tools/ovirt-e2e/drive-console.py, which asserts both
    // that the escalation happened and that it carried a non-empty
    // certificate-subject pin (an empty subject maps to None in
    // build_config, silently disabling verification). Update the consumer
    // if either changes.
    info!(
        %connection_ref,
        hypervisor = %target.hypervisor,
        channel_type = link.channel_type.name(),
        host_subject = %target.host_subject,
        "hypervisor requires TLS; retrying backend connection over the secure port"
    );
    let mut secure_config = base_config;
    // `port` is unused once tls_port is set; the crate dials tls_port.
    secure_config.tls_port = Some(target.secure_port as u16);
    connect_once(&secure_config, link).await
}

/// Build the base `ConnectionConfig` from an authorized `Target`.
///
/// For a direct target the ports are set per attempt by the caller (insecure
/// first, TLS on the `need_secured` retry), so `tls_port` starts `None` here.
/// For a tunnelled target the config is final: `host` is the connect host the
/// proxy is asked for, `tls_port` is `secure_port`, and `proxy` is the parsed
/// `proxy_uri`. Extracted from `run` so the several `Target` field mappings
/// (host fallback, always-`Some` ticket, empty-string -> `None`, the tunnel)
/// are unit-testable in isolation.
///
/// Fails only for a tunnel that cannot be dialled: an empty connect host, a
/// secure port that is not a TCP port, or a proxy URI the crate refuses. The
/// errors name the field, never the connect host, which is a credential.
fn build_config(target: &pb::Target) -> Result<ConnectionConfig> {
    let mut config = ConnectionConfig {
        // `host`: prefer the numeric hypervisor_ip when the control plane
        // provided one, else the hypervisor name. Replaced below for a tunnel.
        host: if target.hypervisor_ip.is_empty() {
            target.hypervisor.clone()
        } else {
            target.hypervisor_ip.clone()
        },
        port: target.insecure_port as u16,
        tls_port: None,
        // The crate encrypts even an empty ticket; an empty ticket is valid for
        // the shakenfist/openstack sources, so always pass Some(...).
        password: Some(target.ticket.clone()),
        ca_cert: if target.ca_cert.is_empty() {
            None
        } else {
            Some(target.ca_cert.clone())
        },
        // Enforcement lives in the ryll crate's verifier: when set, the TLS
        // handshake fails unless the backend cert's subject matches (subject
        // pinning per spice-common semantics, substituting for hostname
        // verification). An empty Target.host_subject still maps to None,
        // i.e. unpinned.
        host_subject: if target.host_subject.is_empty() {
            None
        } else {
            Some(target.host_subject.clone())
        },
        proxy: None,
    };

    let Some(tunnel) = &target.tunnel else {
        return Ok(config);
    };
    // A tunnel without a host_subject is refused by SpiceClient::new, so it
    // is deliberately not checked here as well.
    if tunnel.connect_host.is_empty() {
        return Err(anyhow!("tunnelled target has an empty tunnel.connect_host"));
    }
    let tls_port = match u16::try_from(target.secure_port) {
        Ok(port) if port != 0 => port,
        _ => {
            return Err(anyhow!(
                "tunnelled target has secure_port {}, which is not a TCP port",
                target.secure_port
            ))
        }
    };
    let proxy = parse_proxy_uri(&tunnel.proxy_uri)
        .map_err(|e| anyhow!("tunnelled target has an unusable tunnel.proxy_uri: {e}"))?;

    // Under a tunnel hypervisor_ip and insecure_port are never dialled: the
    // crate dials the proxy and asks it to CONNECT to host:tls_port.
    config.host = tunnel.connect_host.clone();
    config.port = tls_port;
    config.tls_port = Some(tls_port);
    config.proxy = Some(proxy);
    Ok(config)
}

/// What the backend link handshake advertises: the client's channel identity
/// and the capabilities forwarded from it.
struct BackendLink {
    connection_id: u32,
    channel_type: ChannelType,
    channel_id: u8,
    common_caps: Vec<u32>,
    channel_caps: Vec<u32>,
}

/// Log what the backend granted, and warn when it lacks a channel
/// capability the client leg already offered the client.
///
/// The client-leg reply is sent before the backend is known (it carries the
/// ticket key), so Kerbside offers the caps spice-server normally
/// advertises for the channel type (`caps::reply_channel_caps`). A backend
/// built without, say, Opus or LZ4 then lacks a cap the client was told it
/// has, and the client may send something that server refuses. That cannot
/// be undone at this point, but it should be visible.
///
/// Only the channel word is compared. Every common capability Kerbside
/// offers (`caps::REPLY_COMMON_CAPS`) is one the backend leg cannot work
/// without -- the relay frames on MINI_HEADER, and the ticket exchange
/// needs AUTH_SELECTION and AUTH_SPICE -- so a backend lacking one never
/// gets here: `connect_channel_with_caps` refuses the reply
/// (`SpiceLinkReply::check_client_requirements`) and the connect fails.
fn log_backend_caps(
    connection_ref: &str,
    channel_type: ChannelType,
    link: &BackendLink,
    reply: &SpiceLinkReply,
) {
    debug!(
        %connection_ref,
        channel_type = channel_type.name(),
        sent_common_caps = ?link.common_caps,
        sent_channel_caps = ?link.channel_caps,
        backend_common_caps = ?reply.common_caps,
        backend_channel_caps = ?reply.channel_caps,
        "backend link capabilities"
    );
    let missing_channel =
        caps::missing_caps(caps::reply_channel_caps(channel_type), &reply.channel_caps);
    if !missing_channel.is_empty() {
        warn!(
            %connection_ref,
            channel_type = channel_type.name(),
            ?missing_channel,
            backend_channel_caps = ?reply.channel_caps,
            "backend lacks capabilities Kerbside offered the client; the client may \
             send messages this backend does not support"
        );
    }
}

/// One backend connect attempt: build a `SpiceClient` from the config and open
/// the requested channel, advertising the forwarded client caps. Returns the
/// stream and the backend's link reply. TLS is used iff
/// `config.tls_port.is_some()`.
///
/// Bounded by `BACKEND_CONNECT_TIMEOUT` so a hypervisor that accepts TCP but
/// stalls the handshake cannot pin the connection's permit forever. A timeout
/// is a hard failure -- its message deliberately does not match
/// `is_need_secured`, so a stalled insecure attempt is not mistaken for a
/// "requires TLS" signal and does not trigger the secure retry.
async fn connect_once(
    config: &ConnectionConfig,
    link: &BackendLink,
) -> Result<(SpiceStream, SpiceLinkReply)> {
    // `ConnectionConfig` is not Copy; clone it so callers can reuse/adjust the
    // base config across attempts.
    let client = SpiceClient::new(config.clone())?;
    match tokio::time::timeout(
        BACKEND_CONNECT_TIMEOUT,
        client.connect_channel_with_caps(
            link.connection_id,
            link.channel_type,
            link.channel_id,
            &link.common_caps,
            &link.channel_caps,
        ),
    )
    .await
    {
        Ok(result) => result,
        Err(_elapsed) => Err(anyhow!(
            "backend connect timed out after {}s",
            BACKEND_CONNECT_TIMEOUT.as_secs()
        )),
    }
}

/// The raw TCP socket underneath a `SpiceStream`, whichever variant it is.
/// The tokio-rustls streams' `get_ref()` returns `(io, connection)`.
pub(crate) fn tcp_of(stream: &SpiceStream) -> &TcpStream {
    match stream {
        SpiceStream::Plain(tcp) => tcp,
        SpiceStream::Tls(tls) => tls.get_ref().0,
        SpiceStream::TlsServer(tls) => tls.get_ref().0,
    }
}

/// Cap `SO_RCVBUF` on the backend-leg socket.
///
/// Left alone, the receive buffer autotunes up to `net.ipv4.tcp_rmem`'s
/// maximum (commonly 6 MiB) and keeps the TCP window to spice-server open
/// while the relay is blocked writing to a slow client, so the display
/// backlog sits in the proxy. Capping it moves that backlog into
/// spice-server's socket; it does not shrink it, because spice-server's
/// per-channel ACK window is what bounds it (see
/// docs/performance/proxy-backpressure.md). Setting `SO_RCVBUF` explicitly
/// also turns off receive autotuning for the socket.
///
/// The ryll crate dials the socket, so this runs after connect. That cannot
/// shrink the window scale negotiated in the SYN, but the scale only sets
/// the maximum advertisable window; the buffer still bounds what is
/// actually advertised from here on. Linux doubles the value to allow for
/// bookkeeping overhead, so a read-back reports twice what was set, and
/// clamps the request to `net.core.rmem_max` (commonly 212992) first.
///
/// `bytes` of 0 leaves the kernel default in place. Best-effort, like the
/// client-leg options: a failure is logged and NON-fatal.
fn set_backend_rcvbuf(stream: &SpiceStream, bytes: u32, connection_ref: &str) {
    if bytes == 0 {
        return;
    }
    if let Err(e) = SockRef::from(tcp_of(stream)).set_recv_buffer_size(bytes as usize) {
        warn!(
            %connection_ref,
            bytes,
            error = %e,
            "setting backend SO_RCVBUF failed; continuing"
        );
    }
}

/// The audit message for a failed hypervisor connect. Rendered with `{:#}`
/// so the whole error chain survives: ryll wraps each connect stage in
/// context ("TLS handshake with <addr>"), and plain Display prints only that
/// outermost context, dropping the cause an operator needs (rustls's
/// `NotValidForName` for a host_subject mismatch, an unknown CA, and so on).
fn connect_failure_message(err: &Error) -> String {
    format!("Hypervisor connection failed: {err:#}")
}

/// Record the hypervisor-connect-failure audit event. Best-effort: audit RPC
/// errors are logged, not propagated, so the original connect error still
/// reaches the caller. The ticket is never logged.
async fn record_connect_failure(
    state: &SharedState,
    connection_ref: &str,
    channel_type: ChannelType,
    target: &pb::Target,
    err: &Error,
) {
    warn!(
        %connection_ref,
        hypervisor = %target.hypervisor,
        tunnelled = target.tunnel.is_some(),
        channel_type = channel_type.name(),
        error = %format_args!("{err:#}"),
        "hypervisor connection failed"
    );
    let message = connect_failure_message(err);
    if let Err(e) = state
        .rpc
        .record_audit_event(
            &target.source,
            &target.uuid,
            &target.session_id,
            channel_type.name(),
            &state.node_name,
            connection_ref,
            &message,
        )
        .await
    {
        warn!(%connection_ref, error = %e, "recording hypervisor-connect-failure audit event failed");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::anyhow;
    use shakenfist_spice_protocol::proxy::HttpProxy;

    /// A stand-in for a signed CONNECT host, shaped like Proxmox's. It must
    /// never appear in an error kerbside builds.
    const SENTINEL_CONNECT_HOST: &str = "pvespiceproxy:sentinel-0d15ea5e:100:pve1:61000::cafe";

    /// `build_config` for a target without a tunnel, which never fails.
    fn direct_config(target: &pb::Target) -> ConnectionConfig {
        build_config(target).expect("a target without a tunnel always builds")
    }

    /// A target with every field set, tunnelled through `proxy_uri`.
    fn tunnelled_target(proxy_uri: &str, connect_host: &str, secure_port: u32) -> pb::Target {
        pb::Target {
            hypervisor: "pve1".to_string(),
            hypervisor_ip: "192.0.2.1".to_string(),
            insecure_port: 5900,
            secure_port,
            ticket: "vmticket".to_string(),
            ca_cert: "-----BEGIN CERT-----".to_string(),
            host_subject: "CN=pve1".to_string(),
            source: "src".to_string(),
            uuid: "uuid".to_string(),
            session_id: "session".to_string(),
            tunnel: Some(pb::Tunnel {
                proxy_uri: proxy_uri.to_string(),
                connect_host: connect_host.to_string(),
            }),
        }
    }

    /// Build a tunnelled config that must fail, and return its error text,
    /// checked for the sentinel in both its Display and Debug forms.
    fn tunnel_refusal(target: &pb::Target) -> String {
        let err = build_config(target).expect_err("the tunnel must be refused");
        let shown = format!("{err:#}");
        assert!(
            !shown.contains(SENTINEL_CONNECT_HOST)
                && !format!("{err:?}").contains(SENTINEL_CONNECT_HOST),
            "the error quotes the connect host"
        );
        shown
    }

    #[test]
    fn connect_failure_message_keeps_the_cause() {
        // ryll wraps the rustls error in the stage's context; the audit
        // message must still name the cause, or a host_subject refusal
        // reads the same as any other failed handshake.
        let err = anyhow!("invalid peer certificate: NotValidForName")
            .context("TLS handshake with 127.0.0.1:5911");
        assert_eq!(
            connect_failure_message(&err),
            "Hypervisor connection failed: TLS handshake with 127.0.0.1:5911: \
             invalid peer certificate: NotValidForName"
        );
    }

    #[test]
    fn is_need_secured_matches_crate_message() {
        // The exact message SpiceClient::connect_channel_with_caps returns
        // for SpiceError::NeedSecured.
        let err = anyhow!("Server requires TLS connection. Use tls-port in config.");
        assert!(is_need_secured(&err));
    }

    #[test]
    fn is_need_secured_matches_down_the_chain() {
        let inner = anyhow!("Server requires TLS connection. Use tls-port in config.");
        let wrapped = inner.context("connecting backend channel");
        assert!(is_need_secured(&wrapped));
    }

    #[test]
    fn is_need_secured_rejects_unrelated_errors() {
        assert!(!is_need_secured(&anyhow!("connection refused")));
        assert!(!is_need_secured(&anyhow!(
            "TLS handshake failed: bad certificate"
        )));
        assert!(!is_need_secured(&anyhow!("invalid ticket")));
    }

    #[test]
    fn is_need_secured_rejects_host_subject_mismatch() {
        // A pinned host_subject that doesn't match the presented certificate
        // is a hard TLS failure, not a "requires TLS" signal -- it must NOT
        // trigger the insecure-then-secure retry.
        assert!(!is_need_secured(&anyhow!(
            "TLS: rejecting certificate: pinned host_subject C=US,CN=hv: \
             certificate subject does not match"
        )));
    }

    #[test]
    fn connect_timeout_message_is_not_mistaken_for_need_secured() {
        // A stalled insecure attempt must surface as a hard failure, not be
        // retried over TLS -- so the timeout message must not match.
        let err = anyhow!(
            "backend connect timed out after {}s",
            BACKEND_CONNECT_TIMEOUT.as_secs()
        );
        assert!(!is_need_secured(&err));
    }

    #[test]
    fn build_config_prefers_hypervisor_ip_when_present() {
        let target = pb::Target {
            hypervisor: "hv.example".to_string(),
            hypervisor_ip: "10.0.0.5".to_string(),
            insecure_port: 5901,
            ticket: "vmticket".to_string(),
            ..Default::default()
        };
        let config = direct_config(&target);
        assert_eq!(config.host, "10.0.0.5");
        assert_eq!(config.port, 5901);
        assert!(config.tls_port.is_none());
    }

    #[test]
    fn build_config_falls_back_to_hypervisor_name_without_ip() {
        let target = pb::Target {
            hypervisor: "hv.example".to_string(),
            hypervisor_ip: String::new(),
            ..Default::default()
        };
        assert_eq!(direct_config(&target).host, "hv.example");
    }

    #[test]
    fn build_config_always_passes_some_ticket_even_when_empty() {
        // An empty ticket is valid for the shakenfist/openstack sources; the
        // crate encrypts even an empty ticket, so it must stay Some(...).
        let empty = direct_config(&pb::Target::default());
        assert_eq!(empty.password.as_deref(), Some(""));

        let set = direct_config(&pb::Target {
            ticket: "secret".to_string(),
            ..Default::default()
        });
        assert_eq!(set.password.as_deref(), Some("secret"));
    }

    #[test]
    fn build_config_maps_empty_ca_cert_and_host_subject_to_none() {
        let empty = direct_config(&pb::Target::default());
        assert!(empty.ca_cert.is_none());
        assert!(empty.host_subject.is_none());

        let set = direct_config(&pb::Target {
            ca_cert: "-----BEGIN CERT-----".to_string(),
            host_subject: "C=US,CN=hv".to_string(),
            ..Default::default()
        });
        assert_eq!(set.ca_cert.as_deref(), Some("-----BEGIN CERT-----"));
        assert_eq!(set.host_subject.as_deref(), Some("C=US,CN=hv"));
    }

    #[test]
    fn build_config_preserves_escaped_comma_in_host_subject() {
        // The crate parses the subject's spice-common escaping; the proxy
        // must pass it through byte-for-byte rather than mangling it.
        let target = pb::Target {
            host_subject: "O=Acme\\, Inc,CN=hv".to_string(),
            ..Default::default()
        };
        assert_eq!(
            direct_config(&target).host_subject.as_deref(),
            Some("O=Acme\\, Inc,CN=hv")
        );
    }

    #[test]
    fn build_config_without_a_tunnel_maps_exactly_as_before() {
        // Every field set, secure_port included: a direct target still
        // starts insecure, with no proxy, whatever else it carries.
        let target = pb::Target {
            tunnel: None,
            ..tunnelled_target("", "", 5901)
        };
        let config = direct_config(&target);
        assert_eq!(config.host, "192.0.2.1");
        assert_eq!(config.port, 5900);
        assert!(config.tls_port.is_none());
        assert_eq!(config.password.as_deref(), Some("vmticket"));
        assert_eq!(config.ca_cert.as_deref(), Some("-----BEGIN CERT-----"));
        assert_eq!(config.host_subject.as_deref(), Some("CN=pve1"));
        assert!(config.proxy.is_none());
    }

    #[test]
    fn build_config_maps_a_tunnel_to_tls_through_the_proxy() {
        let target = tunnelled_target("http://pve1.example:3128", SENTINEL_CONNECT_HOST, 61000);
        let config = build_config(&target).expect("a well-formed tunnel builds");
        // The proxy is asked to CONNECT to connect_host:secure_port, over TLS.
        // Compared without assert_eq!, whose failure would print the host.
        assert!(
            config.host == SENTINEL_CONNECT_HOST,
            "host is not the connect host"
        );
        assert_eq!(config.tls_port, Some(61000));
        assert_eq!(
            config.proxy,
            Some(HttpProxy {
                host: "pve1.example".to_string(),
                port: 3128,
            })
        );
        // Neither hypervisor_ip nor insecure_port survives to be dialled.
        assert_eq!(config.port, 61000);
        // The credentials and the pin pass through unchanged.
        assert_eq!(config.password.as_deref(), Some("vmticket"));
        assert_eq!(config.ca_cert.as_deref(), Some("-----BEGIN CERT-----"));
        assert_eq!(config.host_subject.as_deref(), Some("CN=pve1"));
    }

    #[test]
    fn build_config_refuses_a_tunnel_with_an_empty_connect_host() {
        let target = tunnelled_target("http://pve1.example:3128", "", 61000);
        assert!(tunnel_refusal(&target).contains("connect_host"));
    }

    #[test]
    fn build_config_refuses_a_tunnel_without_a_usable_secure_port() {
        for port in [0, 65536] {
            let target = tunnelled_target("http://pve1.example:3128", SENTINEL_CONNECT_HOST, port);
            let message = tunnel_refusal(&target);
            assert!(message.contains("secure_port"), "port {port}: {message}");
        }
    }

    #[test]
    fn build_config_refuses_a_tunnel_with_a_bad_proxy_uri() {
        // An empty URI, a scheme the crate refuses, and a port out of range.
        for uri in ["", "https://pve1.example:3128", "http://pve1.example:99999"] {
            let target = tunnelled_target(uri, SENTINEL_CONNECT_HOST, 61000);
            let message = tunnel_refusal(&target);
            assert!(message.contains("proxy_uri"), "uri {uri:?}: {message}");
        }
    }

    /// Build a connected loopback pair: (accepted server side, client side).
    async fn loopback_pair() -> (TcpStream, TcpStream) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("binding a loopback listener");
        let addr = listener.local_addr().expect("local_addr");
        let connect = tokio::spawn(async move { TcpStream::connect(addr).await });
        let (server, _peer) = listener.accept().await.expect("accept");
        let client = connect.await.expect("connect task").expect("connect");
        (server, client)
    }

    /// The receive-buffer cap must apply to a connected (post-connect) socket
    /// reached through the `SpiceStream` wrapper, and 0 must be a no-op.
    #[tokio::test]
    async fn set_backend_rcvbuf_on_loopback_takes_effect() {
        let (_server, client) = loopback_pair().await;
        let stream = SpiceStream::Plain(client);
        let before = SockRef::from(tcp_of(&stream))
            .recv_buffer_size()
            .expect("reading SO_RCVBUF");

        set_backend_rcvbuf(&stream, 0, "test");
        assert_eq!(
            SockRef::from(tcp_of(&stream))
                .recv_buffer_size()
                .expect("reading SO_RCVBUF"),
            before
        );

        // 128 KiB: below the common net.core.rmem_max (212992), which
        // silently clamps larger SO_RCVBUF requests from unprivileged code.
        set_backend_rcvbuf(&stream, 131_072, "test");
        let after = SockRef::from(tcp_of(&stream))
            .recv_buffer_size()
            .expect("reading SO_RCVBUF");
        // Linux clamps the request to net.core.rmem_max (and a small floor),
        // then doubles it on read-back; other platforms report it as set.
        // The exact value is only predictable where rmem_max admits the
        // request, so a host with a lower (or unreadable) rmem_max gets the
        // bound alone rather than a failure that reads as a code defect.
        if cfg!(target_os = "linux") {
            assert!(after <= 262_144, "SO_RCVBUF read back as {after}");
            let rmem_max = std::fs::read_to_string("/proc/sys/net/core/rmem_max")
                .ok()
                .and_then(|s| s.trim().parse::<usize>().ok());
            if rmem_max.is_some_and(|m| m >= 131_072) {
                assert_eq!(after, 262_144);
            }
        } else {
            assert!(after >= 131_072, "SO_RCVBUF read back as {after}");
        }
    }
}
