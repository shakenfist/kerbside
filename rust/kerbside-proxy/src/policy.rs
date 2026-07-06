//! The relay's inspection policy seam.
//!
//! Every framed SPICE message the relay pumps in either direction is passed
//! through a [`Policy`] before it is forwarded. Phase 3 ships only
//! [`PermissivePolicy`], which forwards everything; phase 4 fills this seam
//! with L0 (framing / size / rate) and L1 (per-channel, per-direction
//! message-type allowlist) firewall enforcement without reshaping the relay.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use shakenfist_spice_protocol::messages::MessageHeader;
use shakenfist_spice_protocol::ChannelType;
use tracing::warn;

use crate::allowlist::{classify, MsgClass};
use crate::metrics;

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
/// [`EnforcingPolicy`] constructs `Forward` and `Terminate` (the latter is the
/// default verdict for an L1 grammar violation on a modeled channel). `Drop` is
/// retained in the API for future L2/L3 use (e.g. defanging) — no v1 rule emits
/// it, because dropping a SPICE message mid-stream desynchronises the channel
/// (phase-4 plan, Design decision 3). The narrow `#[allow(dead_code)]` on the
/// `Drop` variant keeps it in the API without a warning until such a rule
/// exists; the relay already handles all three verdicts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Forward the message to the peer, unchanged.
    Forward,
    /// Silently drop the message (do not forward it) but keep the session
    /// alive and continue relaying subsequent messages.
    #[allow(dead_code)]
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
/// enforcement is deferred to phase 4. Phase 4's relay uses [`EnforcingPolicy`]
/// instead; `PermissivePolicy` is retained as the `Policy`-trait baseline the
/// relay/pump unit tests exercise, hence `#[allow(dead_code)]`.
#[allow(dead_code)]
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

/// How the firewall acts on a rule that decides to block a message.
///
/// Settled with the operator (phase-4 plan, Design decision 3): the default
/// ships enforcing, with a first-class `WarnOnly` mode for confidence-building.
/// Structured so the mode can later be made per-direction without a data-model
/// change (a single global mode is enough for v1).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum EnforcementMode {
    /// A rule's blocking verdict (`Drop`/`Terminate`) is applied, and recorded
    /// with `action = enforced`.
    #[default]
    Enforce,
    /// A rule's blocking verdict is **downgraded to [`Verdict::Forward`]** (the
    /// session is never blocked) but recorded with `action = observed` plus a
    /// `tracing::warn!`. This lets an operator run real traffic and see exactly
    /// what enforcement WOULD have tripped before flipping to `Enforce`.
    ///
    /// `#[allow(dead_code)]`: only tests select this today; step 4e constructs
    /// it from the `FirewallPolicy` delivered over gRPC.
    #[allow(dead_code)]
    WarnOnly,
}

/// A firewall rule that fired for one framed message. The variant selects the
/// `rule` metric/audit label; it is low-cardinality and extensible (4c adds
/// size/rate rules).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Rule {
    /// L1: a modeled channel+direction received a message type not in its
    /// grammar (a real grammar violation).
    DisallowedType,
    /// L1: a message arrived on a channel with no modeled grammar. Always
    /// observe-only — never a type-based terminate (Design decision 4).
    UnmodeledType,
}

impl Rule {
    /// The stable `rule` label used in metrics and the audit summary.
    fn label(self) -> &'static str {
        match self {
            Rule::DisallowedType => "disallowed_type",
            Rule::UnmodeledType => "unmodeled_type",
        }
    }
}

/// Whether a recorded verdict was actually applied or merely observed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Action {
    /// The blocking verdict was applied (`Enforce` mode).
    Enforced,
    /// The blocking verdict was suppressed (`WarnOnly` mode), or the rule is
    /// intrinsically observe-only (unmodeled channel).
    Observed,
}

impl Action {
    /// The stable `action` label used in metrics and the audit summary.
    fn label(self) -> &'static str {
        match self {
            Action::Enforced => "enforced",
            Action::Observed => "observed",
        }
    }
}

/// Every known SPICE channel type (`ChannelType` discriminants 1..=11), so the
/// "permit all" default can be built without depending on the crate exposing an
/// iterator.
const ALL_CHANNELS: [ChannelType; 11] = [
    ChannelType::Main,
    ChannelType::Display,
    ChannelType::Inputs,
    ChannelType::Cursor,
    ChannelType::Playback,
    ChannelType::Record,
    ChannelType::Tunnel,
    ChannelType::Smartcard,
    ChannelType::Usbredir,
    ChannelType::Port,
    ChannelType::Webdav,
];

/// The set of channel types a deployment permits the proxy to relay.
///
/// Represented as a bitmask keyed by the `ChannelType` discriminant (1..=11).
/// The enforcement point (denying a forbidden channel before relay) is wired in
/// step 4e when the policy arrives over gRPC; today the default permits every
/// channel, so there is no behavioural gap.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PermittedChannels(u16);

impl PermittedChannels {
    /// Permit every known channel type (the enforcing default; no regression
    /// versus today's relay, which relays any channel `session.rs` accepts).
    pub fn all() -> Self {
        let mut mask = 0u16;
        for ch in ALL_CHANNELS {
            mask |= 1u16 << (ch as u16);
        }
        PermittedChannels(mask)
    }

    /// Whether `ch` is in the permitted set.
    ///
    /// `#[allow(dead_code)]`: reached only via [`FirewallPolicy::channel_permitted`],
    /// whose enforcement point is wired in step 4e.
    #[allow(dead_code)]
    fn contains(self, ch: ChannelType) -> bool {
        self.0 & (1u16 << (ch as u16)) != 0
    }
}

/// The tunable firewall knobs for one connection, delivered per-connection.
///
/// Shared across the two relay directions as an `Arc<FirewallPolicy>` so the
/// allowlist lookup needs no lock on the hot path (phase-4 plan, Design
/// decision 2). This holds only the deployment-tunable knobs; the L1 allowlist
/// tables themselves are a compiled-in fact about the SPICE protocol
/// (`allowlist.rs`), not policy. L0 (size/rate) knobs are added in step 4c.
///
/// `Default` is **enforcing** and permits ALL known channel types.
#[derive(Clone, Debug)]
pub struct FirewallPolicy {
    /// Whether blocking verdicts are applied or merely observed.
    pub mode: EnforcementMode,
    /// The verdict for an L1 grammar violation (disallowed message type) on a
    /// MODELED channel. Defaults to [`Verdict::Terminate`] (fail closed).
    pub disallowed_type_verdict: Verdict,
    /// Which channel types may be relayed. Enforced in step 4e (hence the field
    /// is not yet read: `#[allow(dead_code)]`).
    #[allow(dead_code)]
    permitted_channels: PermittedChannels,
}

impl Default for FirewallPolicy {
    fn default() -> Self {
        FirewallPolicy {
            mode: EnforcementMode::Enforce,
            disallowed_type_verdict: Verdict::Terminate,
            permitted_channels: PermittedChannels::all(),
        }
    }
}

impl FirewallPolicy {
    /// Whether `ch` may be relayed under this policy.
    ///
    /// The enforcement point that consults this (denying a forbidden channel
    /// before relay, in `session.rs`) is wired in step 4e, once the policy is
    /// delivered over gRPC. The default permits every channel, so defining it
    /// now introduces no behavioural gap.
    ///
    /// `#[allow(dead_code)]`: the caller (the pre-relay channel gate in
    /// `session.rs`) is wired in step 4e.
    #[allow(dead_code)]
    pub fn channel_permitted(&self, ch: ChannelType) -> bool {
        self.permitted_channels.contains(ch)
    }
}

/// A per-connection tally of firewall verdicts, shared (lock-free) by both
/// relay directions.
///
/// Firewall violations must NOT emit one audit event per message (a hostile or
/// broken peer could flood them). Instead both directions increment this small
/// fixed set of atomics on the (cold) violation path, and `relay::run` reads it
/// once after the `select!` to emit a single coalesced summary audit event per
/// connection. The `Allowed` hot path never touches it.
#[derive(Debug, Default)]
pub struct VerdictTally {
    disallowed_enforced: AtomicU64,
    disallowed_observed: AtomicU64,
    unmodeled_enforced: AtomicU64,
    unmodeled_observed: AtomicU64,
}

impl VerdictTally {
    /// A fresh, empty tally.
    pub fn new() -> Self {
        Self::default()
    }

    /// Increment the counter for one `(rule, action)` verdict. Lock-free;
    /// called only on the cold violation path, never for `Allowed`.
    fn record(&self, rule: Rule, action: Action) {
        let counter = match (rule, action) {
            (Rule::DisallowedType, Action::Enforced) => &self.disallowed_enforced,
            (Rule::DisallowedType, Action::Observed) => &self.disallowed_observed,
            (Rule::UnmodeledType, Action::Enforced) => &self.unmodeled_enforced,
            (Rule::UnmodeledType, Action::Observed) => &self.unmodeled_observed,
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    /// Format a single summary line describing every verdict recorded on this
    /// connection, or `None` if nothing was recorded (so the caller sends no
    /// audit event). Carries only channel-agnostic rule/action counts — no
    /// ticket or token.
    pub fn summary(&self) -> Option<String> {
        let de = self.disallowed_enforced.load(Ordering::Relaxed);
        let dobs = self.disallowed_observed.load(Ordering::Relaxed);
        let ue = self.unmodeled_enforced.load(Ordering::Relaxed);
        let uobs = self.unmodeled_observed.load(Ordering::Relaxed);
        if de + dobs + ue + uobs == 0 {
            return None;
        }

        let mut parts = Vec::new();
        if de + dobs > 0 {
            parts.push(format!("disallowed_type (enforced={de}, observed={dobs})"));
        }
        if ue + uobs > 0 {
            parts.push(format!("unmodeled_type (enforced={ue}, observed={uobs})"));
        }
        Some(format!(
            "Firewall verdicts this connection: {}",
            parts.join(", ")
        ))
    }
}

/// The phase-4 enforcing policy: L1 message-type grammar enforcement.
///
/// One instance per relay direction, all sharing the connection's
/// `Arc<FirewallPolicy>` config and its `Arc<VerdictTally>` (Design decision 2).
/// `inspect` consults the compiled-in L1 allowlist ([`crate::allowlist`]) on the
/// already-parsed message header only; it never inspects the body (L1 is
/// type-only). L0 (size/rate) enforcement is added in step 4c.
pub struct EnforcingPolicy {
    policy: Arc<FirewallPolicy>,
    dir: Direction,
    tally: Arc<VerdictTally>,
}

impl EnforcingPolicy {
    /// Build the enforcing policy for one direction, sharing the connection's
    /// config and verdict tally.
    pub fn new(policy: Arc<FirewallPolicy>, dir: Direction, tally: Arc<VerdictTally>) -> Self {
        EnforcingPolicy { policy, dir, tally }
    }

    /// Record a verdict to both the global metrics and the per-connection tally.
    fn record(&self, rule: Rule, channel: ChannelType, action: Action) {
        metrics::record_firewall_verdict(channel.name(), self.dir, rule.label(), action.label());
        self.tally.record(rule, action);
    }

    /// Apply a blocking verdict subject to the enforcement mode, recording it.
    ///
    /// This is the single place the warn-only downgrade lives: in `Enforce` the
    /// `would_be` verdict is applied and recorded `enforced`; in `WarnOnly` it
    /// is recorded `observed` (plus a `warn!`) and downgraded to `Forward`.
    fn apply(&self, rule: Rule, channel: ChannelType, would_be: Verdict) -> Verdict {
        match self.policy.mode {
            EnforcementMode::Enforce => {
                self.record(rule, channel, Action::Enforced);
                would_be
            }
            EnforcementMode::WarnOnly => {
                self.record(rule, channel, Action::Observed);
                warn!(
                    channel = channel.name(),
                    direction = ?self.dir,
                    rule = rule.label(),
                    would_be = ?would_be,
                    "firewall WarnOnly: would have blocked; forwarding"
                );
                Verdict::Forward
            }
        }
    }
}

impl Policy for EnforcingPolicy {
    fn inspect(
        &mut self,
        dir: Direction,
        channel: ChannelType,
        header: &MessageHeader,
        _payload: &[u8],
    ) -> Verdict {
        // One EnforcingPolicy serves one direction; the relay passes the
        // matching direction. Recording uses `self.dir`.
        debug_assert_eq!(dir, self.dir);
        match classify(channel, dir, header.message_type) {
            // The hot common case: do NOT record (that would lock/inc on every
            // message). Just forward.
            MsgClass::Allowed => Verdict::Forward,
            // A real grammar violation on a modeled channel: apply the
            // configured verdict subject to the enforcement mode.
            MsgClass::Disallowed => self.apply(
                Rule::DisallowedType,
                channel,
                self.policy.disallowed_type_verdict,
            ),
            // Unmodeled channel: L0-only + observe, never a type-based
            // terminate — even in Enforce mode (Design decision 4).
            MsgClass::ChannelUnmodeled => {
                self.record(Rule::UnmodeledType, channel, Action::Observed);
                Verdict::Forward
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shakenfist_spice_protocol::constants::inputs_client;

    /// A representative `(channel, direction, opcode)` the allowlist classifies
    /// as `Allowed`: an inputs-client mouse position message.
    const ALLOWED_TYPE: u16 = inputs_client::MOUSE_POSITION; // 112
    /// A representative `Disallowed` type: a bogus opcode on the modeled
    /// inputs-client grammar.
    const DISALLOWED_TYPE: u16 = 9999;

    fn header(message_type: u16) -> MessageHeader {
        MessageHeader {
            message_type,
            message_size: 0,
        }
    }

    /// Build an inputs client->server `EnforcingPolicy` in the given mode, plus
    /// a shared tally to assert against.
    fn inputs_policy(mode: EnforcementMode) -> (EnforcingPolicy, Arc<VerdictTally>) {
        let policy = Arc::new(FirewallPolicy {
            mode,
            ..FirewallPolicy::default()
        });
        let tally = Arc::new(VerdictTally::new());
        let engine = EnforcingPolicy::new(policy, Direction::ClientToServer, Arc::clone(&tally));
        (engine, tally)
    }

    fn inspect(engine: &mut EnforcingPolicy, ch: ChannelType, msg_type: u16) -> Verdict {
        engine.inspect(Direction::ClientToServer, ch, &header(msg_type), &[])
    }

    // --- FirewallPolicy defaults / channel permit. ---

    #[test]
    fn default_policy_is_enforcing_and_permits_all_channels() {
        let p = FirewallPolicy::default();
        assert_eq!(p.mode, EnforcementMode::Enforce);
        assert_eq!(p.disallowed_type_verdict, Verdict::Terminate);
        for ch in ALL_CHANNELS {
            assert!(p.channel_permitted(ch), "default must permit {ch:?}");
        }
    }

    // --- Enforce mode. ---

    #[test]
    fn enforce_allowed_forwards_without_recording() {
        let (mut engine, tally) = inputs_policy(EnforcementMode::Enforce);
        assert_eq!(
            inspect(&mut engine, ChannelType::Inputs, ALLOWED_TYPE),
            Verdict::Forward
        );
        // The hot path must not touch the tally.
        assert!(tally.summary().is_none(), "Allowed must not be recorded");
    }

    #[test]
    fn enforce_disallowed_terminates_and_records_enforced() {
        let (mut engine, tally) = inputs_policy(EnforcementMode::Enforce);
        assert_eq!(
            inspect(&mut engine, ChannelType::Inputs, DISALLOWED_TYPE),
            Verdict::Terminate
        );
        assert_eq!(tally.disallowed_enforced.load(Ordering::Relaxed), 1);
        assert_eq!(tally.disallowed_observed.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn enforce_unmodeled_forwards_and_records_observed() {
        let (mut engine, tally) = inputs_policy(EnforcementMode::Enforce);
        // Record is an unmodeled channel: even in Enforce, observe-only.
        assert_eq!(
            inspect(&mut engine, ChannelType::Record, DISALLOWED_TYPE),
            Verdict::Forward
        );
        assert_eq!(tally.unmodeled_observed.load(Ordering::Relaxed), 1);
        assert_eq!(tally.unmodeled_enforced.load(Ordering::Relaxed), 0);
    }

    // --- WarnOnly mode: same inputs, never blocks. ---

    #[test]
    fn warn_only_disallowed_forwards_but_records_observed() {
        let (mut engine, tally) = inputs_policy(EnforcementMode::WarnOnly);
        // The SAME Disallowed input that terminates under Enforce.
        assert_eq!(
            inspect(&mut engine, ChannelType::Inputs, DISALLOWED_TYPE),
            Verdict::Forward
        );
        assert_eq!(tally.disallowed_observed.load(Ordering::Relaxed), 1);
        assert_eq!(tally.disallowed_enforced.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn warn_only_allowed_forwards_without_recording() {
        let (mut engine, tally) = inputs_policy(EnforcementMode::WarnOnly);
        assert_eq!(
            inspect(&mut engine, ChannelType::Inputs, ALLOWED_TYPE),
            Verdict::Forward
        );
        assert!(tally.summary().is_none());
    }

    // --- Mixed sequence: the tally reflects enforced vs observed correctly. ---

    #[test]
    fn tally_reflects_mixed_sequence() {
        let (mut engine, tally) = inputs_policy(EnforcementMode::Enforce);
        // Two disallowed (enforced), one allowed (not recorded), one unmodeled
        // (observed).
        inspect(&mut engine, ChannelType::Inputs, DISALLOWED_TYPE);
        inspect(&mut engine, ChannelType::Inputs, DISALLOWED_TYPE);
        inspect(&mut engine, ChannelType::Inputs, ALLOWED_TYPE);
        inspect(&mut engine, ChannelType::Record, 101);

        assert_eq!(tally.disallowed_enforced.load(Ordering::Relaxed), 2);
        assert_eq!(tally.disallowed_observed.load(Ordering::Relaxed), 0);
        assert_eq!(tally.unmodeled_observed.load(Ordering::Relaxed), 1);
    }

    // --- Both directions share ONE tally. ---

    #[test]
    fn both_directions_share_one_tally() {
        let policy = Arc::new(FirewallPolicy::default());
        let tally = Arc::new(VerdictTally::new());
        let mut c2s = EnforcingPolicy::new(
            Arc::clone(&policy),
            Direction::ClientToServer,
            Arc::clone(&tally),
        );
        let mut s2c = EnforcingPolicy::new(
            Arc::clone(&policy),
            Direction::ServerToClient,
            Arc::clone(&tally),
        );

        c2s.inspect(
            Direction::ClientToServer,
            ChannelType::Inputs,
            &header(DISALLOWED_TYPE),
            &[],
        );
        s2c.inspect(
            Direction::ServerToClient,
            ChannelType::Display,
            &header(DISALLOWED_TYPE),
            &[],
        );

        assert_eq!(tally.disallowed_enforced.load(Ordering::Relaxed), 2);
    }

    // --- Summary formatting. ---

    #[test]
    fn summary_is_none_when_empty() {
        assert!(VerdictTally::new().summary().is_none());
    }

    #[test]
    fn summary_mentions_both_rules_with_counts() {
        let tally = VerdictTally::new();
        // N disallowed + M unmodeled.
        tally.record(Rule::DisallowedType, Action::Enforced);
        tally.record(Rule::DisallowedType, Action::Enforced);
        tally.record(Rule::DisallowedType, Action::Observed);
        tally.record(Rule::UnmodeledType, Action::Observed);

        let summary = tally.summary().expect("non-empty tally has a summary");
        assert!(summary.contains("disallowed_type"), "summary: {summary}");
        assert!(summary.contains("unmodeled_type"), "summary: {summary}");
        assert!(summary.contains("enforced=2"), "summary: {summary}");
        assert!(summary.contains("observed=1"), "summary: {summary}");
    }
}
