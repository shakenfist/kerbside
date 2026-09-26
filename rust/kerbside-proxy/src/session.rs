//! The per-connection SPICE session: the client-facing link handshake and
//! authorization, driving ticket decryption over the ryll server-role
//! handshake drivers.
//!
//! `handle_connection` is the seam `listen::run_secure` hands each accepted
//! (TLS-terminated) client connection to. It:
//!
//! 1. reads the client's link message (`read_link_mess`),
//! 2. maps and validates the requested channel type, and refuses a client
//!    whose common capabilities lack MINI_HEADER or AUTH_SELECTION with a
//!    link error (see `crate::caps`),
//! 3. records the pre-authorization channel identity (`RegisterChannel`),
//! 4. generates a fresh per-connection RSA keypair and replies with the
//!    success link reply (DER public key, and the per-channel-type caps from
//!    `crate::caps::reply_channel_caps`) so the client encrypts its ticket to
//!    us (`send_link_reply`),
//! 5. reads and decrypts the ticket (`read_auth_ticket`),
//! 6. authorizes the token against the gRPC control service
//!    (`AuthorizeConnection`), sending the client the protocol-correct
//!    `SpiceError` on denial/failure, and
//! 7. on success, hands the authorized stream off to the backend leg + relay
//!    (`crate::backend::run`), along with the client's link capabilities,
//!    which the backend leg forwards to the hypervisor.
//!
//! Every path that gets as far as a successful `RegisterChannel`
//! deregisters on teardown, and no path panics: a hostile or broken client
//! must never affect other connections.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use std::collections::HashMap;
use std::sync::Mutex;

use anyhow::{Context, Result};
use shakenfist_spice_protocol::link::{
    generate_ticket_keypair, read_auth_ticket, read_link_mess, send_auth_result, send_link_reply,
    SpiceLinkReply, SpiceStream,
};
use shakenfist_spice_protocol::{ChannelType, SpiceError};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::caps::{self, ClientCaps};
use crate::metrics;
use crate::rpc::{AuthzOutcome, KerbsideRpc};

/// One session's cancellation state: a token shared by all the session's live
/// channel connections, and a refcount of those connections.
struct SessionEntry {
    token: CancellationToken,
    refs: usize,
}

/// A `session_id -> CancellationToken` registry so the control plane can drop
/// every in-flight channel of a session at once (`TerminateSession`).
///
/// A SPICE session is several channels, each its own connection/task; they all
/// share one [`CancellationToken`] keyed by `session_id`, so cancelling it
/// tears the whole session down. Entries are refcounted and removed when the
/// last channel of a session ends. This node only ever tracks the channels it
/// hosts (a load balancer may place other channels of the same session on other
/// nodes, which each terminate their own — see the distributed-deployment note
/// in `docs/proxy-architecture.md`). All methods are short synchronous map
/// operations; the `std::sync::Mutex` is never held across an `.await`.
#[derive(Default)]
pub struct SessionRegistry {
    inner: Mutex<HashMap<String, SessionEntry>>,
}

impl SessionRegistry {
    /// Register a channel of `session_id`, returning the session's shared
    /// cancellation token (created on the first channel of the session).
    pub fn register(&self, session_id: &str) -> CancellationToken {
        let mut map = self.inner.lock().expect("session registry mutex poisoned");
        let entry = map
            .entry(session_id.to_string())
            .or_insert_with(|| SessionEntry {
                token: CancellationToken::new(),
                refs: 0,
            });
        entry.refs += 1;
        entry.token.clone()
    }

    /// Deregister a channel of `session_id`; drop the entry (and its token) when
    /// its last channel ends.
    pub fn deregister(&self, session_id: &str) {
        let mut map = self.inner.lock().expect("session registry mutex poisoned");
        if let Some(entry) = map.get_mut(session_id) {
            entry.refs -= 1;
            if entry.refs == 0 {
                map.remove(session_id);
            }
        }
    }

    /// Cancel every live channel of `session_id`. Returns whether the session
    /// was present; terminating an unknown/already-gone session is a harmless
    /// no-op (idempotent), so the caller need not check.
    pub fn terminate(&self, session_id: &str) -> bool {
        let map = self.inner.lock().expect("session registry mutex poisoned");
        match map.get(session_id) {
            Some(entry) => {
                entry.token.cancel();
                true
            }
            None => false,
        }
    }

    /// Cancel every live session (graceful shutdown). Returns how many were
    /// cancelled. Each session's relays then tear down cleanly, so a drain can
    /// wait for the active-connection count to fall to zero.
    pub fn terminate_all(&self) -> usize {
        let map = self.inner.lock().expect("session registry mutex poisoned");
        for entry in map.values() {
            entry.token.cancel();
        }
        map.len()
    }
}

/// Shared, cheaply-cloneable process state handed to every connection task.
///
/// Wrapped in an `Arc` by `main` and cloned per accepted connection. The
/// `KerbsideRpc` client is itself cheap to clone (it shares a lazily-connected
/// tonic channel), so cloning the `Arc` is the only cost per connection.
pub struct SharedState {
    pub rpc: KerbsideRpc,
    pub node_name: String,
    /// Per-session cancellation registry: the `ProxyControl` consumer
    /// terminates a session by cancelling its token here. Held behind its own
    /// `Arc` so it can be cloned into the ProxyControl consumer task and the
    /// shutdown drain independently of the rest of `SharedState`.
    pub sessions: Arc<SessionRegistry>,
    /// `SO_RCVBUF` cap applied to each backend-leg socket once connected
    /// (`--backend-rcvbuf-bytes`); 0 leaves the kernel's autotuning alone.
    pub backend_rcvbuf_bytes: u32,
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

    // Refuse a client that cannot speak what the relay and the ticket
    // exchange depend on, before anything is recorded for it: a link error
    // the client can report, rather than an auth read that misparses or a
    // relay that misframes. This is not an audit event: nothing about the
    // client is authenticated yet, so there is no console to attribute it
    // to, and a write per unauthenticated connection is the unbounded audit
    // table growth kerbside/api.py's pre-verify rejections avoid.
    let missing = caps::missing_required_client_caps(&link.common_caps);
    if !missing.is_empty() {
        info!(
            %peer, %connection_ref,
            channel = channel_type_name,
            missing = %missing.join(", "),
            common_caps = ?link.common_caps,
            "client lacks required SPICE common capabilities; refusing link"
        );
        let reply = SpiceLinkReply::error_reply(SpiceError::VersionMismatch);
        match tokio::time::timeout(HANDSHAKE_TIMEOUT, send_link_reply(&mut stream, &reply)).await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => debug!(%peer, %connection_ref, error = %e, "sending link refusal failed"),
            Err(_) => debug!(%peer, %connection_ref, "sending link refusal timed out"),
        }
        return;
    }
    let client_caps = ClientCaps {
        common: link.common_caps,
        channel: link.channel_caps,
    };

    let client_ip = peer.ip().to_string();
    let client_port = peer.port() as u32;

    // Record the pre-authorization channel identity via the RegisterChannel
    // RPC. A control-plane failure here means we cannot safely proceed, and
    // nothing was registered, so no deregister is owed.
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
        &client_caps,
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
    client_caps: &ClientCaps,
) -> Result<()> {
    // Fresh per-connection RSA keypair for the ticket exchange. The private
    // key never leaves this function (the `rsa` types are not a direct
    // dependency of this crate), so keypair generation lives beside its only
    // uses -- the reply's public key and the ticket decryption below.
    let (priv_key, der) =
        generate_ticket_keypair().context("generating per-connection RSA keypair")?;

    // Send the success link reply (carrying our DER public key and the caps
    // Kerbside offers for this channel type) and read + decrypt the client's
    // ticket, both under the handshake time bound. The reply cannot depend on
    // the backend, which is not chosen until the ticket is authorized. The
    // recovered token is never logged.
    let token = tokio::time::timeout(HANDSHAKE_TIMEOUT, async {
        let reply = SpiceLinkReply {
            error: SpiceError::Ok,
            pub_key: der,
            common_caps: caps::REPLY_COMMON_CAPS.to_vec(),
            channel_caps: caps::reply_channel_caps(channel_type).to_vec(),
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
            // Send the protocol-correct PermissionDenied so the client reports
            // it, rather than just dropping the connection. The token is never
            // logged; the human-readable reason is.
            metrics::record_denied();
            info!(%peer, %connection_ref, %reason, "connection denied by control service");
            send_auth_result(&mut stream, SpiceError::PermissionDenied)
                .await
                .ok();
            Ok(())
        }
        Ok(AuthzOutcome::Target { target, policy }) => {
            // Channel-level firewall gate: even with a valid token, a channel
            // type the deployment forbids must not be relayed. Deny before the
            // relay -- protocol-correctly (PermissionDenied) -- and audit it.
            // The default policy permits every channel, so this never fires
            // unless a deployment restricts `permitted_channels`.
            if !policy.channel_permitted(channel_type) {
                metrics::record_denied();
                warn!(
                    %peer, %connection_ref,
                    channel = channel_type.name(),
                    "channel type not permitted by firewall policy; denying"
                );
                if let Err(e) = state
                    .rpc
                    .record_audit_event(
                        &target.source,
                        &target.uuid,
                        &target.session_id,
                        channel_type.name(),
                        &state.node_name,
                        connection_ref,
                        "Channel type not permitted by firewall policy",
                    )
                    .await
                {
                    warn!(%connection_ref, error = %e, "recording firewall channel-denied audit event failed");
                }
                send_auth_result(&mut stream, SpiceError::PermissionDenied)
                    .await
                    .ok();
                return Ok(());
            }

            // Authorized and channel permitted: tell the client, then hand the
            // stream to the backend leg + relay with the policy the control
            // service delivered. `stream` is moved into `backend::run`.
            metrics::record_authorized();
            send_auth_result(&mut stream, SpiceError::Ok).await?;
            // Register this channel under its session so a control-plane
            // TerminateSession can cancel the whole session's relays; the token
            // is threaded into the relay. Deregister on every exit path (incl.
            // a backend-connect error), pairing with the register above.
            let cancel = state.sessions.register(&target.session_id);
            let result = crate::backend::run(
                state,
                Arc::new(policy),
                connection_ref,
                stream,
                connection_id,
                channel_type,
                channel_id,
                client_caps,
                &target,
                cancel,
            )
            .await;
            state.sessions.deregister(&target.session_id);
            result
        }
    }
}

#[cfg(test)]
mod tests {
    use super::SessionRegistry;
    use shakenfist_spice_protocol::ChannelType;

    #[test]
    fn registry_shares_one_token_per_session_and_refcounts() {
        let reg = SessionRegistry::default();
        // Two channels of the same session share one token.
        let a = reg.register("sess-1");
        let b = reg.register("sess-1");
        assert!(!a.is_cancelled());
        // Terminating cancels the shared token seen by both channels.
        assert!(reg.terminate("sess-1"));
        assert!(a.is_cancelled());
        assert!(b.is_cancelled());
        // Refcount: still one live entry until BOTH channels deregister.
        reg.deregister("sess-1");
        assert!(
            reg.terminate("sess-1"),
            "entry must survive until the last channel deregisters"
        );
        reg.deregister("sess-1");
        assert!(
            !reg.terminate("sess-1"),
            "entry must be gone after the last channel deregisters"
        );
    }

    #[test]
    fn terminate_unknown_session_is_a_noop() {
        let reg = SessionRegistry::default();
        assert!(!reg.terminate("never-registered"));
        // A fresh registration after an unknown terminate still works and is
        // not pre-cancelled.
        let t = reg.register("sess-2");
        assert!(!t.is_cancelled());
    }

    #[test]
    fn distinct_sessions_have_independent_tokens() {
        let reg = SessionRegistry::default();
        let one = reg.register("sess-a");
        let two = reg.register("sess-b");
        reg.terminate("sess-a");
        assert!(one.is_cancelled());
        assert!(
            !two.is_cancelled(),
            "terminating one session must not affect another"
        );
    }

    #[test]
    fn terminate_all_cancels_every_registered_session() {
        let reg = SessionRegistry::default();
        let a = reg.register("s-a");
        let b = reg.register("s-b");
        assert_eq!(reg.terminate_all(), 2, "both sessions counted");
        assert!(a.is_cancelled());
        assert!(b.is_cancelled());
    }

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

/// The whole client-to-backend handshake, driven through `handle_connection`
/// over loopback TCP: a fake SPICE client, the mock control service from
/// `rpc.rs`, and a fake hypervisor built from ryll's server-role drivers.
#[cfg(test)]
mod handshake_tests {
    use super::*;

    use shakenfist_spice_protocol::constants::capabilities;
    use shakenfist_spice_protocol::link::{perform_auth, perform_link_with_caps, SpiceLinkMess};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::oneshot;

    use crate::pb;
    use crate::rpc::tests::{spawn_mock_with, MockService};

    /// Bound on each whole test, so a handshake bug fails rather than hangs.
    const TEST_TIMEOUT: Duration = Duration::from_secs(60);

    const VM_TICKET: &str = "vm-ticket";

    /// What the fake hypervisor saw of the backend leg's link message.
    #[derive(Debug)]
    struct BackendSaw {
        connection_id: u32,
        channel_type: u8,
        channel_id: u8,
        common_caps: Vec<u32>,
        channel_caps: Vec<u32>,
    }

    /// A one-shot fake hypervisor: accept one connection, record its link
    /// message, reply with `reply_channel_caps`, check the ticket Kerbside
    /// sends, grant auth, then hold the connection until the relay closes it.
    async fn spawn_fake_backend(
        reply_channel_caps: Vec<u32>,
    ) -> (u16, oneshot::Receiver<BackendSaw>) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind backend");
        let port = listener.local_addr().expect("backend addr").port();
        let (tx, rx) = oneshot::channel();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("backend accept");
            let link = read_link_mess(&mut stream)
                .await
                .expect("backend read link");
            let _ = tx.send(BackendSaw {
                connection_id: link.connection_id,
                channel_type: link.channel_type,
                channel_id: link.channel_id,
                common_caps: link.common_caps,
                channel_caps: link.channel_caps,
            });
            let (key, der) = generate_ticket_keypair().expect("backend keypair");
            let reply = SpiceLinkReply {
                error: SpiceError::Ok,
                pub_key: der,
                common_caps: vec![11],
                channel_caps: reply_channel_caps,
            };
            send_link_reply(&mut stream, &reply)
                .await
                .expect("backend link reply");
            let ticket = read_auth_ticket(&mut stream, &key)
                .await
                .expect("backend ticket");
            assert_eq!(ticket, VM_TICKET, "Kerbside must send the target's ticket");
            send_auth_result(&mut stream, SpiceError::Ok)
                .await
                .expect("backend auth result");
            let mut sink = Vec::new();
            let _ = stream.read_to_end(&mut sink).await;
        });
        (port, rx)
    }

    /// Start a proxy accept loop for one connection over plain TCP (the TLS
    /// termination in `listen.rs` is not under test here), backed by `mock`.
    /// Returns the proxy address, the audit log, and the connection task.
    async fn spawn_proxy(
        mock: MockService,
    ) -> (
        SocketAddr,
        Arc<Mutex<Vec<String>>>,
        tokio::task::JoinHandle<()>,
        tempfile::TempDir,
    ) {
        let audit = Arc::clone(&mock.audit_messages);
        let (rpc, dir) = spawn_mock_with(mock).await;
        let state = Arc::new(SharedState {
            rpc,
            node_name: "test-node".to_string(),
            sessions: Arc::new(SessionRegistry::default()),
            backend_rcvbuf_bytes: 0,
        });
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind proxy");
        let addr = listener.local_addr().expect("proxy addr");
        let task = tokio::spawn(async move {
            let (tcp, peer) = listener.accept().await.expect("proxy accept");
            handle_connection(state, SpiceStream::Plain(tcp), peer).await;
        });
        (addr, audit, task, dir)
    }

    /// A client with capabilities no Ryll build advertises -- display bits
    /// GL_SCANOUT(7), CODEC_VP8(10), CODEC_VP9(13) and CODEC_H265(14), a
    /// top bit, and a second word in both sets -- is forwarded to the
    /// backend verbatim, and is offered the display row of the reply table
    /// rather than the old fixed caps.
    #[tokio::test]
    async fn client_caps_reach_the_backend_and_reply_caps_follow_channel_type() {
        tokio::time::timeout(TEST_TIMEOUT, async {
            let client_common = [
                capabilities::AUTH_SELECTION
                    | capabilities::AUTH_SPICE
                    | capabilities::MINI_HEADER
                    | (1 << 30),
                0x0000_0005,
            ];
            let client_channel = [
                (1 << 7) | (1 << 10) | (1 << 13) | (1 << 14) | (1 << 31),
                0xdead_beef,
            ];

            // The backend lacks PREF_VIDEO_CODEC_TYPE, which Kerbside offered
            // the client, exercising the mismatch warning path.
            let backend_caps = vec![
                capabilities::DISPLAY_MONITORS_CONFIG
                    | capabilities::DISPLAY_PREF_COMPRESSION
                    | capabilities::DISPLAY_STREAM_REPORT,
            ];
            let (backend_port, backend_saw) = spawn_fake_backend(backend_caps).await;
            let mock = MockService {
                target: Some(pb::Target {
                    hypervisor: "fake-hv".to_string(),
                    hypervisor_ip: "127.0.0.1".to_string(),
                    insecure_port: backend_port as u32,
                    secure_port: 0,
                    ticket: VM_TICKET.to_string(),
                    source: "src".to_string(),
                    uuid: "uuid".to_string(),
                    session_id: "session".to_string(),
                    ..Default::default()
                }),
                // Empty means every channel type is permitted.
                permitted_channels: Some(vec![]),
                ..Default::default()
            };
            let (proxy_addr, audit, proxy_task, _dir) = spawn_proxy(mock).await;

            let mut client = TcpStream::connect(proxy_addr)
                .await
                .expect("client connect");
            let reply = perform_link_with_caps(
                &mut client,
                0x1234_5678,
                ChannelType::Display,
                2,
                &client_common,
                &client_channel,
            )
            .await
            .expect("client link");
            assert_eq!(reply.error, SpiceError::Ok);
            assert_eq!(reply.common_caps, caps::REPLY_COMMON_CAPS.to_vec());
            assert_eq!(
                reply.channel_caps,
                caps::reply_channel_caps(ChannelType::Display).to_vec()
            );
            perform_auth(&mut client, &reply.pub_key, Some("good-token"))
                .await
                .expect("client auth through the proxy");

            let saw = backend_saw.await.expect("backend saw a link");
            assert_eq!(saw.connection_id, 0x1234_5678);
            assert_eq!(saw.channel_type, ChannelType::Display as u8);
            assert_eq!(saw.channel_id, 2);
            // Verbatim, multi-word included, apart from the auth mechanism
            // bits (AUTH_SPICE was already set, so nothing changes here).
            assert_eq!(saw.common_caps, client_common.to_vec());
            assert_eq!(saw.channel_caps, client_channel.to_vec());

            // Closing the client ends the relay and the connection task.
            drop(client);
            proxy_task.await.expect("proxy connection task");
            let audit = audit.lock().expect("audit mutex").clone();
            assert!(
                audit
                    .iter()
                    .any(|m| m == "Hypervisor connection successful"),
                "audit events: {audit:?}"
            );
        })
        .await
        .expect("handshake test timed out");
    }

    /// A client lacking MINI_HEADER, or AUTH_SELECTION, gets a link error
    /// before any key exchange, control-plane call or backend dial.
    #[tokio::test]
    async fn client_without_required_common_caps_is_refused_at_link() {
        tokio::time::timeout(TEST_TIMEOUT, async {
            for common in [
                capabilities::AUTH_SELECTION | capabilities::AUTH_SPICE,
                capabilities::AUTH_SPICE | capabilities::MINI_HEADER,
            ] {
                let (proxy_addr, audit, proxy_task, _dir) =
                    spawn_proxy(MockService::default()).await;
                let mut client = TcpStream::connect(proxy_addr)
                    .await
                    .expect("client connect");
                let link = SpiceLinkMess {
                    connection_id: 0,
                    channel_type: ChannelType::Main as u8,
                    channel_id: 0,
                    common_caps: vec![common],
                    channel_caps: vec![capabilities::DEFAULT_MAIN],
                };
                client
                    .write_all(&link.serialize())
                    .await
                    .expect("client link");

                let mut buf = Vec::new();
                client.read_to_end(&mut buf).await.expect("read link reply");
                let reply = SpiceLinkReply::parse(&buf).expect("parse link reply");
                assert_eq!(
                    reply.error,
                    SpiceError::VersionMismatch,
                    "common caps {common:#x}"
                );
                assert!(reply.common_caps.is_empty());
                assert!(reply.channel_caps.is_empty());

                proxy_task.await.expect("proxy connection task");
                assert!(audit.lock().expect("audit mutex").is_empty());
            }
        })
        .await
        .expect("refusal test timed out");
    }
}
