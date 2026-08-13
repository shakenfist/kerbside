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
//!   `channel_id`) to replay onto the backend link handshake, and
//! - `target`, the authorized upstream descriptor (hypervisor host/ip, secure
//!   / insecure ports, ticket, CA cert, host subject) to build a
//!   `ConnectionConfig` from.
//!
//! 3e builds the `ConnectionConfig` from `target`, connects via `SpiceClient`
//! with a `need_secured` retry (which the crate does not perform itself),
//! emits the hypervisor connect success/failure audit events, and then hands
//! the two streams to the relay seam (`crate::relay::run`, a stub until 3f).

use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Error, Result};
use shakenfist_spice_protocol::link::SpiceStream;
use shakenfist_spice_protocol::{ChannelType, ConnectionConfig, SpiceClient};
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

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
/// crate not exposing a typed `NeedSecured` error -- `SpiceClient::connect_channel`
/// maps `SpiceError::NeedSecured` to `anyhow!("Server requires TLS connection.
/// Use tls-port in config.")`, so we have nothing to match on but the message.
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

/// Connect to the hypervisor (with the proxy-side `need_secured` retry the
/// crate lacks), emit the connect audit events, and hand both streams to the
/// relay.
///
/// Returns `Err` if the backend connection cannot be established (after any
/// retry); the caller closes the client connection and deregisters the channel.
#[allow(clippy::too_many_arguments)]
pub async fn run(
    state: &SharedState,
    policy: Arc<FirewallPolicy>,
    connection_ref: &str,
    client_stream: SpiceStream,
    connection_id: u32,
    channel_type: ChannelType,
    channel_id: u8,
    target: &pb::Target,
    cancel: CancellationToken,
) -> Result<()> {
    // Build the base connection config from the authorized target. The ports
    // are set per attempt below (insecure first, TLS on retry).
    let base_config = build_config(target);

    // Connect with an insecure-first + RetrySecured fallback: attempt the
    // insecure leg and, only on a NeedSecured signal, retry over TLS. Any
    // other failure on the first attempt is returned as-is (no retry).
    let backend_stream = match connect_once(&base_config, connection_id, channel_type, channel_id)
        .await
    {
        Ok(stream) => stream,
        Err(first_err) => {
            // Only retry when the server explicitly asked for a secure
            // connection and we actually have a secure port to try.
            if is_need_secured(&first_err) && target.secure_port != 0 {
                // CI-ORACLE: the message text and the host_subject field are
                // load-bearing for tools/ovirt-e2e/drive-console.py, which
                // asserts both that the escalation happened and that it
                // carried a non-empty certificate-subject pin (an empty
                // subject maps to None in build_config, silently disabling
                // verification). Update the consumer if either changes.
                info!(
                    %connection_ref,
                    hypervisor = %target.hypervisor,
                    channel_type = channel_type.name(),
                    host_subject = %target.host_subject,
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
        session_id = %target.session_id,
        channel_type = channel_type.name(),
        channel_id,
        connection_id,
        "hypervisor connection successful; handing off to relay"
    );

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

/// Build the base `ConnectionConfig` from an authorized `Target`.
///
/// The ports are set per attempt by the caller (insecure first, TLS on the
/// `need_secured` retry), so `tls_port` starts `None` here. Extracted from
/// `run` so the several `Target` field mappings (host fallback, always-`Some`
/// ticket, empty-string -> `None`) are unit-testable in isolation.
fn build_config(target: &pb::Target) -> ConnectionConfig {
    // `host`: prefer the numeric hypervisor_ip when the control plane provided
    // one, else the hypervisor name.
    let host = if target.hypervisor_ip.is_empty() {
        target.hypervisor.clone()
    } else {
        target.hypervisor_ip.clone()
    };
    ConnectionConfig {
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
    }
}

/// One backend connect attempt: build a `SpiceClient` from the config and open
/// the requested channel. TLS is used iff `config.tls_port.is_some()`.
///
/// Bounded by `BACKEND_CONNECT_TIMEOUT` so a hypervisor that accepts TCP but
/// stalls the handshake cannot pin the connection's permit forever. A timeout
/// is a hard failure -- its message deliberately does not match
/// `is_need_secured`, so a stalled insecure attempt is not mistaken for a
/// "requires TLS" signal and does not trigger the secure retry.
async fn connect_once(
    config: &ConnectionConfig,
    connection_id: u32,
    channel_type: ChannelType,
    channel_id: u8,
) -> Result<SpiceStream> {
    // `ConnectionConfig` is not Copy; clone it so callers can reuse/adjust the
    // base config across attempts.
    let client = SpiceClient::new(config.clone())?;
    match tokio::time::timeout(
        BACKEND_CONNECT_TIMEOUT,
        client.connect_channel(connection_id, channel_type, channel_id),
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
        let config = build_config(&target);
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
        assert_eq!(build_config(&target).host, "hv.example");
    }

    #[test]
    fn build_config_always_passes_some_ticket_even_when_empty() {
        // An empty ticket is valid for the shakenfist/openstack sources; the
        // crate encrypts even an empty ticket, so it must stay Some(...).
        let empty = build_config(&pb::Target::default());
        assert_eq!(empty.password.as_deref(), Some(""));

        let set = build_config(&pb::Target {
            ticket: "secret".to_string(),
            ..Default::default()
        });
        assert_eq!(set.password.as_deref(), Some("secret"));
    }

    #[test]
    fn build_config_maps_empty_ca_cert_and_host_subject_to_none() {
        let empty = build_config(&pb::Target::default());
        assert!(empty.ca_cert.is_none());
        assert!(empty.host_subject.is_none());

        let set = build_config(&pb::Target {
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
            build_config(&target).host_subject.as_deref(),
            Some("O=Acme\\, Inc,CN=hv")
        );
    }
}
