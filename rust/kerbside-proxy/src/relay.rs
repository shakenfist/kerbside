//! The inspection-first SPICE relay.
//!
//! STUB (phase 3e): the seam is defined here so the backend leg can hand off
//! both owned streams without reshaping. Phase 3f fills the body with a
//! bidirectional, per-message framed relay (6-byte `MessageHeader`) driven
//! through the `Policy`/`Verdict` seam.
//!
//! The signature is chosen so 3f can implement the framed relay without
//! reshaping the call site:
//!
//! - both `SpiceStream`s are passed by value (the relay owns them for the life
//!   of the session and drives reads/writes on both directions),
//! - `channel_type` is passed so per-channel policy can key off it later, and
//! - `connection_ref` is passed for logging/metrics correlation.

use anyhow::Result;
use shakenfist_spice_protocol::link::SpiceStream;
use shakenfist_spice_protocol::ChannelType;
use tracing::info;

/// Relay the authorized client connection to the connected backend channel.
///
/// STUB (phase 3e): logs that the hypervisor connection is up and drops both
/// streams, closing them. Phase 3f wires the bidirectional framed relay.
pub async fn run(
    client: SpiceStream,
    backend: SpiceStream,
    channel_type: ChannelType,
    connection_ref: &str,
) -> Result<()> {
    info!(
        %connection_ref,
        channel_type = channel_type.name(),
        "connected to hypervisor; relay not yet wired (phase 3f)"
    );

    // Dropping both streams closes them for now; 3f relays between them instead.
    drop(client);
    drop(backend);

    Ok(())
}
