//! The backend leg + relay handoff.
//!
//! This is the seam phase 3e (backend connect) fills and phase 3f (the
//! inspection-first relay) builds on. `run` receives the authorized client
//! `SpiceStream` and everything needed to open the matching hypervisor channel:
//!
//! - `state` for the gRPC client (audit events) and node name,
//! - `connection_ref` for bookkeeping/audit correlation,
//! - `client_stream`, the TLS-terminated, authorized client stream to relay,
//! - the SPICE channel identity (`connection_id`, `channel_type`,
//!   `channel_id`) to replay onto the backend link handshake, and
//! - `target`, the authorized upstream descriptor (hypervisor host/ip, secure
//!   / insecure ports, ticket, CA cert, host subject) to build a
//!   `ConnectionConfig` from.
//!
//! 3e builds the `ConnectionConfig` from `target`, connects via `SpiceClient`
//! with a `need_secured` retry (which the crate does not perform itself),
//! emits the hypervisor connect success/failure audit events, and then hands
//! the two streams to the relay seam (`crate::relay::run`, a stub until 3f).

use anyhow::{Error, Result};
use shakenfist_spice_protocol::link::SpiceStream;
use shakenfist_spice_protocol::{ChannelType, ConnectionConfig, SpiceClient};
use tracing::{info, warn};

use crate::pb;
use crate::session::SharedState;

/// Detect the crate's "server requires TLS" (`NeedSecured`) error.
///
/// FRAGILE: this is a string match over the error chain, forced by the ryll
/// crate not exposing a typed `NeedSecured` error -- `SpiceClient::connect_channel`
/// maps `SpiceError::NeedSecured` to `anyhow!("Server requires TLS connection.
/// Use tls-port in config.")`, so we have nothing to match on but the message.
/// Any other connect failure (refused, TLS handshake, bad ticket, ...) must NOT
/// match here, so we deliberately look only for the distinctive substrings.
///
/// Future work: add a typed `NeedSecured` error (or a dedicated error kind) to
/// the ryll `shakenfist-spice-protocol` crate and match on that instead. Tracked
/// alongside the backend items in `docs/plans/PLAN-rust-proxy.md`.
fn is_need_secured(err: &Error) -> bool {
    err.chain().any(|cause| {
        let msg = cause.to_string().to_lowercase();
        msg.contains("requires tls") || msg.contains("secured")
    })
}

/// Connect to the hypervisor (with the proxy-side `need_secured` retry the
/// crate lacks), emit the connect audit events, and hand both streams to the
/// relay.
///
/// Returns `Err` if the backend connection cannot be established (after any
/// retry); the caller closes the client connection and deregisters the channel.
#[allow(clippy::too_many_arguments)]
pub async fn run(
    state: &SharedState,
    connection_ref: &str,
    client_stream: SpiceStream,
    connection_id: u32,
    channel_type: ChannelType,
    channel_id: u8,
    target: &pb::Target,
) -> Result<()> {
    // Build the base connection config from the authorized target. The ports
    // are set per attempt below (insecure first, TLS on retry).
    //
    // `host`: prefer the numeric hypervisor_ip when the control plane provided
    // one, else the hypervisor name (mirrors proxy.py's server selection).
    let host = if target.hypervisor_ip.is_empty() {
        target.hypervisor.clone()
    } else {
        target.hypervisor_ip.clone()
    };
    let base_config = ConnectionConfig {
        host,
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
        // TODO(host_subject): the ryll crate does NOT enforce host_subject --
        // its CA verifier accepts a hostname/subject mismatch (see
        // client.rs::create_tls_connector). We pass it through for parity, but
        // real hypervisor-cert subject pinning is future work tracked as the
        // "Backend host_subject enforcement" item in docs/plans/PLAN-rust-proxy.md
        // (likely a ryll-crate change). Do NOT rely on this for security here.
        host_subject: if target.host_subject.is_empty() {
            None
        } else {
            Some(target.host_subject.clone())
        },
    };

    // Connect, mirroring proxy.py's insecure-first + RetrySecured fallback:
    // attempt the insecure leg and, only on a NeedSecured signal, retry over
    // TLS. Any other failure on the first attempt is returned as-is (no retry).
    let backend_stream = match connect_once(&base_config, connection_id, channel_type, channel_id)
        .await
    {
        Ok(stream) => stream,
        Err(first_err) => {
            // Only retry when the server explicitly asked for a secure
            // connection and we actually have a secure port to try.
            if is_need_secured(&first_err) && target.secure_port != 0 {
                info!(
                    %connection_ref,
                    hypervisor = %target.hypervisor,
                    channel_type = channel_type.name(),
                    "hypervisor requires TLS; retrying backend connection over the secure port"
                );
                let mut secure_config = base_config;
                // `port` is unused once tls_port is set; the crate dials tls_port.
                secure_config.tls_port = Some(target.secure_port as u16);
                match connect_once(&secure_config, connection_id, channel_type, channel_id).await {
                    Ok(stream) => stream,
                    Err(retry_err) => {
                        record_connect_failure(
                            state,
                            connection_ref,
                            channel_type,
                            target,
                            &retry_err,
                        )
                        .await;
                        return Err(retry_err);
                    }
                }
            } else {
                record_connect_failure(state, connection_ref, channel_type, target, &first_err)
                    .await;
                return Err(first_err);
            }
        }
    };

    // Successful hypervisor connection: record the audit event (mirrors
    // proxy.py:426-429). The ticket is never logged. Audit RPC failures are
    // non-fatal -- log and continue rather than tearing down a live connection.
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
        session_id = %target.session_id,
        channel_type = channel_type.name(),
        channel_id,
        connection_id,
        "hypervisor connection successful; handing off to relay"
    );

    // Hand both owned streams to the relay seam (phase 3f fills the body).
    crate::relay::run(client_stream, backend_stream, channel_type, connection_ref).await
}

/// One backend connect attempt: build a `SpiceClient` from the config and open
/// the requested channel. TLS is used iff `config.tls_port.is_some()`.
async fn connect_once(
    config: &ConnectionConfig,
    connection_id: u32,
    channel_type: ChannelType,
    channel_id: u8,
) -> Result<SpiceStream> {
    // `ConnectionConfig` is not Copy; clone it so callers can reuse/adjust the
    // base config across attempts.
    let client = SpiceClient::new(config.clone())?;
    client
        .connect_channel(connection_id, channel_type, channel_id)
        .await
}

/// Record the hypervisor-connect-failure audit event (mirrors
/// proxy.py:442-446). Best-effort: audit RPC errors are logged, not propagated,
/// so the original connect error still reaches the caller. The ticket is never
/// logged.
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
        channel_type = channel_type.name(),
        error = %err,
        "hypervisor connection failed"
    );
    let message = format!("Hypervisor connection failed: {err}");
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

    #[test]
    fn is_need_secured_matches_crate_message() {
        // The exact message SpiceClient::connect_channel returns for
        // SpiceError::NeedSecured.
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
}
