//! The per-connection SPICE session: the client-facing link handshake and
//! authorization, reproducing `kerbside/proxy.py`'s `ClientPassword` over the
//! ryll server-role handshake drivers.
//!
//! `handle_connection` is the seam `listen::run_secure` hands each accepted
//! (TLS-terminated) client connection to. It:
//!
//! 1. reads the client's link message (`read_link_mess`),
//! 2. maps and validates the requested channel type,
//! 3. records the pre-authorization channel identity (`RegisterChannel`),
//! 4. generates a fresh per-connection RSA keypair and replies with the
//!    success link reply (DER public key, caps 11/9) so the client encrypts
//!    its ticket to us (`send_link_reply`),
//! 5. reads and decrypts the ticket (`read_auth_ticket`),
//! 6. authorizes the token against the gRPC control service
//!    (`AuthorizeConnection`), sending the client the protocol-correct
//!    `SpiceError` on denial/failure, and
//! 7. on success, hands the authorized stream off to the backend leg + relay
//!    (`crate::backend::run`, a stub until phases 3e/3f).
//!
//! Every path that gets as far as a successful `RegisterChannel`
//! deregisters on teardown, and no path panics: a hostile or broken client
//! must never affect other connections.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use shakenfist_spice_protocol::link::{
    generate_ticket_keypair, read_auth_ticket, read_link_mess, send_auth_result, send_link_reply,
    SpiceLinkReply, SpiceStream,
};
use shakenfist_spice_protocol::{ChannelType, SpiceError};
use tracing::{debug, info, warn};

use crate::metrics;
use crate::policy::FirewallPolicy;
use crate::rpc::{AuthzOutcome, KerbsideRpc};

/// Shared, cheaply-cloneable process state handed to every connection task.
///
/// Wrapped in an `Arc` by `main` and cloned per accepted connection. The
/// `KerbsideRpc` client is itself cheap to clone (it shares a lazily-connected
/// tonic channel), so cloning the `Arc` is the only cost per connection.
pub struct SharedState {
    pub rpc: KerbsideRpc,
    pub node_name: String,
}

/// Overall time budget for the client-facing handshake reads/writes (link
/// reply + ticket). The ryll drivers bound memory but not time, so a slow or
/// hostile peer must not be able to stall a connection task indefinitely.
/// This deliberately does *not* cover the backend connect + relay, which run
/// for the life of the SPICE session.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

/// Handle one TLS-terminated SPICE client connection end to end.
///
/// Never panics and never propagates an error: all failures are logged and the
/// connection is dropped. `RegisterChannel` is issued after the link message
/// and, once it succeeds, `DeregisterChannel` runs on every exit path.
pub async fn handle_connection(state: Arc<SharedState>, mut stream: SpiceStream, peer: SocketAddr) {
    let connection_ref = uuid::Uuid::new_v4().to_string();

    // Count this accepted secure connection, and keep `active_connections`
    // accurate for its whole lifetime: the guard decrements on drop, which
    // covers every exit path below (early `return`s included).
    metrics::inc_connections();
    let _connection_guard = metrics::connection_guard();

    // Read the client's link message under a time bound (the driver bounds
    // memory but not time).
    let link = match tokio::time::timeout(HANDSHAKE_TIMEOUT, read_link_mess(&mut stream)).await {
        Ok(Ok(link)) => link,
        Ok(Err(e)) => {
            debug!(%peer, %connection_ref, error = %e, "reading client link message failed");
            return;
        }
        Err(_) => {
            debug!(%peer, %connection_ref, "reading client link message timed out");
            return;
        }
    };

    // Map the requested channel type. `link.channel_type` is a raw u8 off the
    // wire; an unknown/obsolete value (e.g. 0, or the retired Tunnel usage)
    // has no name to report to the control plane, so we close the connection.
    let channel_type = match ChannelType::from_u8(link.channel_type) {
        Some(ct) => ct,
        None => {
            debug!(
                %peer, %connection_ref,
                channel_type = link.channel_type,
                "client requested an unknown SPICE channel type; closing"
            );
            return;
        }
    };
    let channel_type_name = channel_type.name();

    let client_ip = peer.ip().to_string();
    let client_port = peer.port() as u32;

    // Record the pre-authorization channel identity (mirrors proxy.py's
    // record_channel_info in ServerLinkMess). A control-plane failure here
    // means we cannot safely proceed, and nothing was registered, so no
    // deregister is owed.
    if let Err(e) = state
        .rpc
        .register_channel(
            &state.node_name,
            &connection_ref,
            &client_ip,
            client_port,
            link.connection_id,
            channel_type_name,
            link.channel_id as u32,
        )
        .await
    {
        warn!(%peer, %connection_ref, error = %e, "RegisterChannel failed; closing connection");
        return;
    }

    // From here the channel is registered: every exit path must deregister.
    // `serve` owns the rest of the handshake (and, on success, the backend
    // handoff); we deregister once after it returns regardless of outcome.
    let result = serve(
        &state,
        &connection_ref,
        stream,
        peer,
        link.connection_id,
        channel_type,
        link.channel_id,
        channel_type_name,
    )
    .await;
    if let Err(e) = result {
        debug!(%peer, %connection_ref, error = %e, "connection ended with error");
    }

    if let Err(e) = state
        .rpc
        .deregister_channel(&state.node_name, &connection_ref)
        .await
    {
        warn!(%peer, %connection_ref, error = %e, "DeregisterChannel failed");
    }
}

/// The post-registration handshake: reply, ticket, authorization, and (on
/// success) the backend handoff. Returns `Ok(())` for cleanly-handled outcomes
/// (including a denial, where the client is sent `PermissionDenied`) and `Err`
/// for I/O/handshake failures the caller logs at debug. The caller deregisters
/// the channel after this returns, whatever the outcome.
#[allow(clippy::too_many_arguments)]
async fn serve(
    state: &SharedState,
    connection_ref: &str,
    mut stream: SpiceStream,
    peer: SocketAddr,
    connection_id: u32,
    channel_type: ChannelType,
    channel_id: u8,
    channel_type_name: &str,
) -> Result<()> {
    // Fresh per-connection RSA keypair for the ticket exchange. The private
    // key never leaves this function (the `rsa` types are not a direct
    // dependency of this crate), so keypair generation lives beside its only
    // uses -- the reply's public key and the ticket decryption below.
    let (priv_key, der) =
        generate_ticket_keypair().context("generating per-connection RSA keypair")?;

    // Send the success link reply (carrying our DER public key and the
    // caps 11/9 the Python proxy uses) and read + decrypt the client's ticket,
    // both under the handshake time bound. The recovered token is never logged.
    let token = tokio::time::timeout(HANDSHAKE_TIMEOUT, async {
        let reply = SpiceLinkReply {
            error: SpiceError::Ok,
            pub_key: der,
            common_caps: vec![11],
            channel_caps: vec![9],
        };
        send_link_reply(&mut stream, &reply).await?;
        read_auth_ticket(&mut stream, &priv_key).await
    })
    .await
    .context("client handshake (link reply / ticket) timed out")??;

    // Authorize the token against the control service.
    let outcome = state
        .rpc
        .authorize_connection(
            &token,
            connection_ref,
            &peer.ip().to_string(),
            peer.port() as u32,
            connection_id,
            channel_type_name,
            channel_id as u32,
        )
        .await;

    match outcome {
        Err(e) => {
            // A control-plane failure: tell the client the connection errored,
            // then close (the caller deregisters). Logged here at warn.
            warn!(%peer, %connection_ref, error = %e, "AuthorizeConnection RPC failed; closing connection");
            send_auth_result(&mut stream, SpiceError::Error).await.ok();
            Ok(())
        }
        Ok(AuthzOutcome::Denied(reason)) => {
            // Cleaner than proxy.py, which just drops the connection: send the
            // protocol-correct PermissionDenied so the client reports it. The
            // token is never logged; the human-readable reason is.
            metrics::record_denied();
            info!(%peer, %connection_ref, %reason, "connection denied by control service");
            send_auth_result(&mut stream, SpiceError::PermissionDenied)
                .await
                .ok();
            Ok(())
        }
        Ok(AuthzOutcome::Target(target)) => {
            // Authorized: tell the client, then hand the stream to the backend
            // leg + relay. `stream` is moved into `backend::run`.
            metrics::record_authorized();
            send_auth_result(&mut stream, SpiceError::Ok).await?;
            // 4e: replace with the FirewallPolicy delivered in the
            // AuthorizeConnection reply. The compiled default is enforcing and
            // permits every channel, so it is the correct fallback.
            let policy = Arc::new(FirewallPolicy::default());
            crate::backend::run(
                state,
                policy,
                connection_ref,
                stream,
                connection_id,
                channel_type,
                channel_id,
                &target,
            )
            .await
        }
    }
}

#[cfg(test)]
mod tests {
    use shakenfist_spice_protocol::ChannelType;

    /// The channel-type mapping is the contract between the raw link-message
    /// byte and the `channel_type` strings we send to the gRPC control service
    /// (RegisterChannel / AuthorizeConnection). Guard both the accepted values
    /// and their names, and that out-of-range/obsolete bytes are rejected
    /// (handle_connection closes the connection on `None`).
    #[test]
    fn channel_type_mapping_matches_control_plane_names() {
        assert_eq!(ChannelType::from_u8(1).map(|c| c.name()), Some("main"));
        assert_eq!(ChannelType::from_u8(2).map(|c| c.name()), Some("display"));
        assert_eq!(ChannelType::from_u8(9).map(|c| c.name()), Some("usbredir"));
        assert_eq!(ChannelType::from_u8(11).map(|c| c.name()), Some("webdav"));

        // 0 is not a valid channel type, and 12/255 are past the defined range.
        assert!(ChannelType::from_u8(0).is_none());
        assert!(ChannelType::from_u8(12).is_none());
        assert!(ChannelType::from_u8(255).is_none());
    }
}
