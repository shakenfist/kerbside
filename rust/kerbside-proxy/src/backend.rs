//! The backend leg + relay handoff.
//!
//! This is the seam phases 3e (backend connect) and 3f (inspection-first
//! relay) fill. `run` receives the authorized client `SpiceStream` and
//! everything needed to open the matching hypervisor channel:
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
//! with a `need_secured` retry, emits the hypervisor connect success/failure
//! audit events, and then 3f relays between `client_stream` and the connected
//! backend stream. The signature is fixed here so those steps can fill the
//! body without reshaping `session::serve`'s call site.

use anyhow::Result;
use shakenfist_spice_protocol::link::SpiceStream;
use shakenfist_spice_protocol::ChannelType;
use tracing::info;

use crate::pb;
use crate::session::SharedState;

/// Connect to the hypervisor and relay the authorized client connection.
///
/// STUB (phase 3d): logs that authorization succeeded and returns `Ok(())`,
/// dropping the client stream (closing the connection). Phases 3e/3f wire the
/// real backend connect + inspection-first relay.
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
    // Silence the not-yet-used state handle; the backend leg (3e) uses it for
    // RecordAuditEvent. Dropping `client_stream` closes the authorized client
    // connection for now.
    let _ = state;
    drop(client_stream);

    info!(
        %connection_ref,
        hypervisor = %target.hypervisor,
        hypervisor_ip = %target.hypervisor_ip,
        session_id = %target.session_id,
        channel_type = channel_type.name(),
        channel_id,
        connection_id,
        "authorized; backend leg + relay not yet wired (phase 3e/3f)"
    );

    Ok(())
}
