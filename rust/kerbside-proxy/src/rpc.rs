//! gRPC client for the KerbsideProxy control service over a unix domain
//! socket.
//!
//! The Kerbside daemon hosts the `KerbsideProxy` service on a
//! filesystem-guarded unix socket (see `kerbside/rpc/server.py`). tonic has no
//! built-in `unix:` transport, so we build a `Channel` over a custom connector
//! that dials the socket via `tokio::net::UnixStream`. The channel is created
//! lazily so construction is infallible and the channel transparently
//! reconnects if the daemon restarts and re-binds the socket.
//!
//! `KerbsideRpc` wraps the generated stub and exposes typed async methods that
//! build the request messages, call the service, and map results/errors into
//! `anyhow::Result`. tonic clients are cheap to clone (they share the
//! underlying channel), so each method clones the stub for its call.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use tonic::transport::{Channel, Endpoint, Uri};
use tracing::{debug, info, warn};

use crate::pb;
use crate::session::SessionRegistry;
use hyper_util::rt::TokioIo;
use tokio::net::UnixStream;
use tower::service_fn;

/// The outcome of an `AuthorizeConnection` call: either the connection was
/// denied (with a human-readable reason) or authorised with a `Target`
/// describing the upstream hypervisor plus the firewall `policy` the proxy must
/// enforce for the connection. `Target` is boxed because it is much larger than
/// the `Denied` string, keeping the enum compact.
///
/// The `policy` is built from the `firewall_policy` the daemon delivers on the
/// success path ("Python decides policy; Rust enforces it"); an older daemon
/// that omits it falls back to the enforcing [`FirewallPolicy::default`].
#[derive(Debug)]
pub enum AuthzOutcome {
    Denied(String),
    Target {
        target: Box<pb::Target>,
        policy: crate::policy::FirewallPolicy,
    },
}

/// A gRPC client for the KerbsideProxy control service over the UDS.
#[derive(Clone)]
pub struct KerbsideRpc {
    client: pb::kerbside_proxy_client::KerbsideProxyClient<Channel>,
}

/// Build a lazily-connected `Channel` that dials the given unix socket path.
///
/// The HTTP authority in the endpoint URI is a required-but-ignored
/// placeholder: the custom connector always dials `socket_path` regardless of
/// the URI it is handed. `connect_with_connector_lazy` never fails and defers
/// the first connection attempt until a request is issued, so the channel
/// reconnects on its own if the daemon restarts the socket.
fn connect_uds(socket_path: PathBuf) -> Channel {
    Endpoint::try_from("http://[::]:50051")
        .expect("static endpoint URI is valid")
        .connect_with_connector_lazy(service_fn(move |_: Uri| {
            let socket_path = socket_path.clone();
            async move {
                let stream = UnixStream::connect(socket_path).await?;
                Ok::<_, std::io::Error>(TokioIo::new(stream))
            }
        }))
}

/// Check a `StatusReply` and turn an application-level failure into an error.
///
/// Transport/internal failures already surface as `tonic::Status` (mapped to
/// an error by the caller); this only inspects the application-level
/// `success`/`error` fields carried by the bookkeeping RPCs.
fn check_status(reply: pb::StatusReply, what: &str) -> Result<()> {
    if reply.success {
        Ok(())
    } else {
        bail!("{what} failed: {}", reply.error)
    }
}

impl KerbsideRpc {
    /// Connect to the KerbsideProxy service on the given unix socket. This is
    /// infallible: the channel is lazy and only dials the socket on first use.
    pub fn connect(socket_path: &Path) -> Self {
        let channel = connect_uds(socket_path.to_path_buf());
        Self {
            client: pb::kerbside_proxy_client::KerbsideProxyClient::new(channel),
        }
    }

    /// AuthorizeConnection: the core authorization decision. Returns a
    /// `Target` on success or a `Denied` reason on any miss.
    #[allow(clippy::too_many_arguments)]
    pub async fn authorize_connection(
        &self,
        token: &str,
        connection_ref: &str,
        client_ip: &str,
        client_port: u32,
        connection_id: u32,
        channel_type: &str,
        channel_id: u32,
    ) -> Result<AuthzOutcome> {
        let request = pb::AuthorizeConnectionRequest {
            token: token.to_string(),
            connection_ref: connection_ref.to_string(),
            client_ip: client_ip.to_string(),
            client_port,
            connection_id,
            channel_type: channel_type.to_string(),
            channel_id,
        };

        let mut client = self.client.clone();
        let reply = client
            .authorize_connection(request)
            .await
            .context("AuthorizeConnection RPC failed")?
            .into_inner();

        // Present only on the success path; an absent policy falls back to the
        // enforcing compiled default (handles an older daemon that never sets
        // it). Taken before matching `result` since both are fields of `reply`.
        let policy = match reply.firewall_policy {
            Some(fp) => crate::policy::FirewallPolicy::from_proto(fp),
            None => crate::policy::FirewallPolicy::default(),
        };

        match reply.result {
            Some(pb::authorize_connection_reply::Result::Target(target)) => {
                Ok(AuthzOutcome::Target {
                    target: Box::new(target),
                    policy,
                })
            }
            Some(pb::authorize_connection_reply::Result::Denied(denied)) => {
                Ok(AuthzOutcome::Denied(denied.reason))
            }
            None => bail!("AuthorizeConnection reply had no result"),
        }
    }

    /// RegisterChannel: record the pre-authorization channel identity.
    #[allow(clippy::too_many_arguments)]
    pub async fn register_channel(
        &self,
        node: &str,
        connection_ref: &str,
        client_ip: &str,
        client_port: u32,
        connection_id: u32,
        channel_type: &str,
        channel_id: u32,
    ) -> Result<()> {
        let request = pb::RegisterChannelRequest {
            node: node.to_string(),
            connection_ref: connection_ref.to_string(),
            client_ip: client_ip.to_string(),
            client_port,
            connection_id,
            channel_type: channel_type.to_string(),
            channel_id,
        };

        let mut client = self.client.clone();
        let reply = client
            .register_channel(request)
            .await
            .context("RegisterChannel RPC failed")?
            .into_inner();

        check_status(reply, "RegisterChannel")
    }

    /// RecordAuditEvent: write an audit event for this connection.
    #[allow(clippy::too_many_arguments)]
    pub async fn record_audit_event(
        &self,
        source: &str,
        uuid: &str,
        session_id: &str,
        channel: &str,
        node: &str,
        connection_ref: &str,
        message: &str,
    ) -> Result<()> {
        let request = pb::AuditEventRequest {
            source: source.to_string(),
            uuid: uuid.to_string(),
            session_id: session_id.to_string(),
            channel: channel.to_string(),
            node: node.to_string(),
            connection_ref: connection_ref.to_string(),
            message: message.to_string(),
        };

        let mut client = self.client.clone();
        let reply = client
            .record_audit_event(request)
            .await
            .context("RecordAuditEvent RPC failed")?
            .into_inner();

        check_status(reply, "RecordAuditEvent")
    }

    /// DeregisterChannel: remove a channel record at teardown.
    pub async fn deregister_channel(&self, node: &str, connection_ref: &str) -> Result<()> {
        let request = pb::DeregisterChannelRequest {
            node: node.to_string(),
            connection_ref: connection_ref.to_string(),
        };

        let mut client = self.client.clone();
        let reply = client
            .deregister_channel(request)
            .await
            .context("DeregisterChannel RPC failed")?
            .into_inner();

        check_status(reply, "DeregisterChannel")
    }

    /// ClearNodeChannels: clear stale channel records for a node at startup.
    pub async fn clear_node_channels(&self, node: &str) -> Result<()> {
        let request = pb::ClearNodeChannelsRequest {
            node: node.to_string(),
        };

        let mut client = self.client.clone();
        let reply = client
            .clear_node_channels(request)
            .await
            .context("ClearNodeChannels RPC failed")?
            .into_inner();

        check_status(reply, "ClearNodeChannels")
    }

    /// ProxyControl: open the server-streaming control channel and consume it.
    ///
    /// Acts on `TerminateSession` by cancelling the session in `sessions`
    /// (dropping all of this node's in-flight channels for it); heartbeats are
    /// logged. Intended to run as a spawned background task: it loops until the
    /// stream ends or errors, logs the outcome, and returns.
    pub async fn run_proxy_control(
        &self,
        node: String,
        sessions: Arc<SessionRegistry>,
    ) -> Result<()> {
        let request = pb::ProxyControlRequest { node: node.clone() };

        let mut client = self.client.clone();
        let mut stream = client
            .proxy_control(request)
            .await
            .context("ProxyControl RPC failed")?
            .into_inner();

        info!(node = %node, "ProxyControl stream opened");

        loop {
            match stream.message().await {
                Ok(Some(event)) => match event.event {
                    Some(pb::proxy_control_event::Event::Heartbeat(_)) => {
                        debug!(node = %node, "ProxyControl heartbeat");
                    }
                    Some(pb::proxy_control_event::Event::TerminateSession(ts)) => {
                        // Cancel every in-flight channel of the session on this
                        // node. Idempotent: a session we do not host (its
                        // channels may be on other nodes behind a load balancer)
                        // is simply not found.
                        let hit = sessions.terminate(&ts.session_id);
                        info!(
                            node = %node,
                            session_id = %ts.session_id,
                            terminated = hit,
                            "ProxyControl TerminateSession event"
                        );
                    }
                    None => {
                        debug!(node = %node, "ProxyControl event with no payload");
                    }
                },
                Ok(None) => {
                    info!(node = %node, "ProxyControl stream closed by server");
                    return Ok(());
                }
                Err(status) => {
                    warn!(node = %node, %status, "ProxyControl stream error");
                    return Ok(());
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use shakenfist_spice_protocol::ChannelType;
    use tokio::net::UnixListener;
    use tokio_stream::wrappers::UnixListenerStream;
    use tonic::transport::Server;
    use tonic::{Request, Response, Status};

    use crate::pb::kerbside_proxy_server::{KerbsideProxy, KerbsideProxyServer};

    /// A minimal in-process implementation of the service with canned
    /// responses: a `Target` for a known token, `Denied` otherwise, and
    /// `StatusReply { success: true }` for the bookkeeping RPCs.
    #[derive(Default)]
    struct MockService;

    #[tonic::async_trait]
    impl KerbsideProxy for MockService {
        async fn authorize_connection(
            &self,
            request: Request<pb::AuthorizeConnectionRequest>,
        ) -> std::result::Result<Response<pb::AuthorizeConnectionReply>, Status> {
            let req = request.into_inner();
            // On success, deliver a WarnOnly policy permitting only main+inputs,
            // so the client-side proto->FirewallPolicy mapping is exercised.
            let (result, firewall_policy) = if req.token == "good-token" {
                (
                    pb::authorize_connection_reply::Result::Target(pb::Target {
                        hypervisor: "hv1".to_string(),
                        hypervisor_ip: "10.0.0.1".to_string(),
                        insecure_port: 5900,
                        secure_port: 5901,
                        ticket: "ticket".to_string(),
                        ca_cert: "ca".to_string(),
                        host_subject: "CN=hv1".to_string(),
                        source: "src".to_string(),
                        uuid: "uuid".to_string(),
                        session_id: "session".to_string(),
                    }),
                    Some(pb::FirewallPolicy {
                        mode: pb::firewall_policy::Mode::WarnOnly as i32,
                        permitted_channels: vec![1, 3],
                    }),
                )
            } else {
                (
                    pb::authorize_connection_reply::Result::Denied(pb::Denied {
                        reason: "unknown token".to_string(),
                    }),
                    None,
                )
            };
            Ok(Response::new(pb::AuthorizeConnectionReply {
                result: Some(result),
                firewall_policy,
            }))
        }

        async fn register_channel(
            &self,
            _request: Request<pb::RegisterChannelRequest>,
        ) -> std::result::Result<Response<pb::StatusReply>, Status> {
            Ok(Response::new(pb::StatusReply {
                success: true,
                error: String::new(),
            }))
        }

        async fn record_audit_event(
            &self,
            _request: Request<pb::AuditEventRequest>,
        ) -> std::result::Result<Response<pb::StatusReply>, Status> {
            Ok(Response::new(pb::StatusReply {
                success: true,
                error: String::new(),
            }))
        }

        async fn deregister_channel(
            &self,
            _request: Request<pb::DeregisterChannelRequest>,
        ) -> std::result::Result<Response<pb::StatusReply>, Status> {
            Ok(Response::new(pb::StatusReply {
                success: true,
                error: String::new(),
            }))
        }

        async fn clear_node_channels(
            &self,
            _request: Request<pb::ClearNodeChannelsRequest>,
        ) -> std::result::Result<Response<pb::StatusReply>, Status> {
            Ok(Response::new(pb::StatusReply {
                success: true,
                error: String::new(),
            }))
        }

        type ProxyControlStream = tokio_stream::wrappers::ReceiverStream<
            std::result::Result<pb::ProxyControlEvent, Status>,
        >;

        async fn proxy_control(
            &self,
            _request: Request<pb::ProxyControlRequest>,
        ) -> std::result::Result<Response<Self::ProxyControlStream>, Status> {
            // Emit one heartbeat and one TerminateSession, then close.
            let (tx, rx) = tokio::sync::mpsc::channel(2);
            tokio::spawn(async move {
                let _ = tx
                    .send(Ok(pb::ProxyControlEvent {
                        event: Some(pb::proxy_control_event::Event::Heartbeat(pb::Heartbeat {})),
                    }))
                    .await;
                let _ = tx
                    .send(Ok(pb::ProxyControlEvent {
                        event: Some(pb::proxy_control_event::Event::TerminateSession(
                            pb::TerminateSession {
                                session_id: "term-me".to_string(),
                            },
                        )),
                    }))
                    .await;
            });
            Ok(Response::new(tokio_stream::wrappers::ReceiverStream::new(
                rx,
            )))
        }
    }

    /// Spawn the mock server on a unix socket and return a connected client.
    async fn spawn_mock() -> (KerbsideRpc, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let socket_path = dir.path().join("api.sock");

        let listener = UnixListener::bind(&socket_path).expect("bind uds");
        let incoming = UnixListenerStream::new(listener);

        tokio::spawn(async move {
            Server::builder()
                .add_service(KerbsideProxyServer::new(MockService))
                .serve_with_incoming(incoming)
                .await
                .expect("serve");
        });

        // The channel is lazy, so no need to wait for the server to be ready
        // before constructing the client; the first RPC will connect.
        let client = KerbsideRpc::connect(&socket_path);
        (client, dir)
    }

    #[tokio::test]
    async fn authorize_target_and_denied() {
        let (client, _dir) = spawn_mock().await;

        let outcome = client
            .authorize_connection("good-token", "ref", "1.2.3.4", 6000, 1, "main", 0)
            .await
            .expect("authorize good token");
        match outcome {
            AuthzOutcome::Target { target, policy } => {
                assert_eq!(target.hypervisor, "hv1");
                // The delivered policy (WarnOnly, permit main+inputs) must be
                // mapped onto the AuthzOutcome the session then enforces.
                assert_eq!(policy.mode, crate::policy::EnforcementMode::WarnOnly);
                assert!(policy.channel_permitted(ChannelType::Main));
                assert!(policy.channel_permitted(ChannelType::Inputs));
                assert!(!policy.channel_permitted(ChannelType::Display));
            }
            AuthzOutcome::Denied(r) => panic!("expected Target, got Denied({r})"),
        }

        let outcome = client
            .authorize_connection("bad-token", "ref", "1.2.3.4", 6000, 1, "main", 0)
            .await
            .expect("authorize bad token");
        match outcome {
            AuthzOutcome::Denied(reason) => assert_eq!(reason, "unknown token"),
            AuthzOutcome::Target { .. } => panic!("expected Denied, got Target"),
        }
    }

    #[tokio::test]
    async fn bookkeeping_rpcs_succeed() {
        let (client, _dir) = spawn_mock().await;

        client
            .register_channel("node", "ref", "1.2.3.4", 6000, 1, "main", 0)
            .await
            .expect("register_channel");
        client
            .record_audit_event("src", "uuid", "session", "main", "node", "ref", "hello")
            .await
            .expect("record_audit_event");
        client
            .deregister_channel("node", "ref")
            .await
            .expect("deregister_channel");
        client
            .clear_node_channels("node")
            .await
            .expect("clear_node_channels");
    }

    #[tokio::test]
    async fn proxy_control_consumes_stream_and_terminates_session() {
        let (client, _dir) = spawn_mock().await;
        // A session registered here; the mock will emit TerminateSession for it.
        let sessions = Arc::new(crate::session::SessionRegistry::default());
        let token = sessions.register("term-me");
        // The mock emits a heartbeat + a TerminateSession then closes; the
        // consumer should act on the terminate and return Ok once the stream
        // ends.
        client
            .run_proxy_control("node".to_string(), sessions.clone())
            .await
            .expect("run_proxy_control");
        assert!(
            token.is_cancelled(),
            "TerminateSession must cancel the registered session"
        );
    }
}
