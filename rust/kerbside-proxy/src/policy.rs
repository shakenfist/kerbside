//! The relay's inspection policy seam.
//!
//! Every framed SPICE message the relay pumps in either direction is passed
//! through a [`Policy`] before it is forwarded. Phase 3 ships only
//! [`PermissivePolicy`], which forwards everything; phase 4 fills this seam
//! with L0 (framing / size / rate) and L1 (per-channel, per-direction
//! message-type allowlist) firewall enforcement without reshaping the relay.

use shakenfist_spice_protocol::messages::MessageHeader;
use shakenfist_spice_protocol::ChannelType;

/// Which way a framed message is travelling through the relay.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    /// A message the SPICE client sent towards the hypervisor.
    ClientToServer,
    /// A message the hypervisor sent towards the SPICE client.
    ServerToClient,
}

/// What the policy decided should happen to one framed message.
///
/// `Drop` and `Terminate` are the enforcement seam for phase 4: the only
/// policy shipped in phase 3 is [`PermissivePolicy`], which always returns
/// `Forward`, so nothing constructs those variants outside the relay tests
/// yet. `#[allow(dead_code)]` keeps them in the API until phase 4's L0/L1
/// policies use them; the relay already handles all three verdicts.
#[allow(dead_code)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Forward the message to the peer, unchanged.
    Forward,
    /// Silently drop the message (do not forward it) but keep the session
    /// alive and continue relaying subsequent messages.
    Drop,
    /// Tear the whole session down: both relay directions end.
    Terminate,
}

/// Inspects framed SPICE messages and decides their fate.
///
/// The relay calls [`inspect`](Policy::inspect) for every complete message in
/// each direction. `&mut self` lets a phase-4 policy accumulate per-connection
/// state (rate counters, handshake progress, per-surface bookkeeping, ...).
///
/// Each relay direction owns its OWN policy instance in phase 3 (see
/// [`crate::relay::run`]); because [`PermissivePolicy`] is stateless this needs
/// no synchronisation and avoids a shared lock on the hot path. If phase 4
/// needs state shared across the two directions, it can wrap a single policy in
/// an `Arc<Mutex<..>>` (or `tokio::sync::Mutex`) then and construct the two
/// direction views from it.
pub trait Policy: Send {
    /// Inspect one framed SPICE message and decide its fate.
    ///
    /// `payload` is the message body only: the 6-byte [`MessageHeader`] has
    /// already been parsed into `header` and is not included in `payload`.
    fn inspect(
        &mut self,
        dir: Direction,
        channel: ChannelType,
        header: &MessageHeader,
        payload: &[u8],
    ) -> Verdict;
}

/// The phase-3 policy: forward every message unchanged.
///
/// This is the "inspection-first framed relay with a no-op policy" of the
/// master plan's design decision 5 — the framing and the seam are real, the
/// enforcement is deferred to phase 4.
#[derive(Clone, Copy, Debug, Default)]
pub struct PermissivePolicy;

impl Policy for PermissivePolicy {
    fn inspect(
        &mut self,
        _dir: Direction,
        _channel: ChannelType,
        _header: &MessageHeader,
        _payload: &[u8],
    ) -> Verdict {
        Verdict::Forward
    }
}
