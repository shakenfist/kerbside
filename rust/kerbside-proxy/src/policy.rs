//! The relay's inspection policy seam.
//!
//! Every framed SPICE message the relay pumps in either direction is passed
//! through a [`Policy`] before it is forwarded. Phase 3 ships only
//! [`PermissivePolicy`], which forwards everything; phase 4 fills this seam
//! with L0 (framing / size / rate) and L1 (per-channel, per-direction
//! message-type allowlist) firewall enforcement without reshaping the relay.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

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

    /// Inspect a message's header BEFORE its body is buffered (L0).
    ///
    /// The relay calls this as soon as it has parsed the 6-byte
    /// [`MessageHeader`], and before it waits to buffer `message_size` body
    /// bytes — the whole point of the L0 size/rate caps is to refuse a body
    /// the cap forbids without ever accumulating it. The default forwards.
    ///
    /// Only [`Verdict::Forward`] and [`Verdict::Terminate`] are meaningful
    /// here: returning `Terminate` ends the direction without buffering the
    /// body; anything else lets the relay proceed to buffer the body and call
    /// [`inspect`](Policy::inspect). No v1 rule emits `Drop` from a header
    /// check (skipping an un-buffered body is out of scope), so the relay
    /// treats a `Drop` from `check_header` as `Forward`.
    fn check_header(
        &mut self,
        _dir: Direction,
        _channel: ChannelType,
        _header: &MessageHeader,
    ) -> Verdict {
        Verdict::Forward
    }
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
    /// Constructed from the `FirewallPolicy` delivered over gRPC (step 4e) when
    /// the daemon selects `WARN_ONLY`, and by the enforcement-mode unit tests.
    WarnOnly,
}

/// A firewall rule that fired for one framed message. The variant selects the
/// `rule` metric/audit label; it is low-cardinality and extensible.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Rule {
    /// L1: a modeled channel+direction received a message type not in its
    /// grammar (a real grammar violation).
    DisallowedType,
    /// L1: a message arrived on a channel with no modeled grammar. Always
    /// observe-only — never a type-based terminate (Design decision 4).
    UnmodeledType,
    /// L0: a message's declared body size exceeded the per-(channel,direction)
    /// policy cap (which sits below the relay's absolute resource guard).
    SizeCap,
    /// L0: the per-direction message/byte rate exceeded the configured
    /// ceiling (disabled by default — see [`RateLimit`]).
    RateCap,
}

/// The number of [`Rule`] variants; [`VerdictTally`] holds one counter per
/// `(Rule, Action)` pair.
const RULE_COUNT: usize = 4;

impl Rule {
    /// The stable `rule` label used in metrics and the audit summary.
    fn label(self) -> &'static str {
        match self {
            Rule::DisallowedType => "disallowed_type",
            Rule::UnmodeledType => "unmodeled_type",
            Rule::SizeCap => "size_cap",
            Rule::RateCap => "rate_cap",
        }
    }

    /// A dense 0-based index into the tally's per-rule counters.
    fn index(self) -> usize {
        match self {
            Rule::DisallowedType => 0,
            Rule::UnmodeledType => 1,
            Rule::SizeCap => 2,
            Rule::RateCap => 3,
        }
    }

    /// Every rule, in `index` order — for iterating the tally.
    fn all() -> [Rule; RULE_COUNT] {
        [
            Rule::DisallowedType,
            Rule::UnmodeledType,
            Rule::SizeCap,
            Rule::RateCap,
        ]
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

/// The number of [`Action`] variants.
const ACTION_COUNT: usize = 2;

impl Action {
    /// The stable `action` label used in metrics and the audit summary.
    fn label(self) -> &'static str {
        match self {
            Action::Enforced => "enforced",
            Action::Observed => "observed",
        }
    }

    /// A dense 0-based index into the tally's per-action counters.
    fn index(self) -> usize {
        match self {
            Action::Enforced => 0,
            Action::Observed => 1,
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

    /// Build the permitted set from the `ChannelType` discriminants delivered in
    /// the gRPC `FirewallPolicy` (step 4e).
    ///
    /// An EMPTY slice means "permit all" — a deployment that restricts channels
    /// lists the permitted ones, while permitting NONE is nonsensical (it would
    /// block every connection). This mirrors the documented proto contract.
    /// Discriminants outside the known 1..=11 range are ignored (they can never
    /// be relayed: `session.rs` rejects unknown channel types before authz).
    pub fn from_discriminants(discriminants: &[u32]) -> Self {
        if discriminants.is_empty() {
            return Self::all();
        }
        let mut mask = 0u16;
        for &d in discriminants {
            if (1..=11).contains(&d) {
                mask |= 1u16 << d;
            }
        }
        PermittedChannels(mask)
    }

    /// Whether `ch` is in the permitted set.
    fn contains(self, ch: ChannelType) -> bool {
        self.0 & (1u16 << (ch as u16)) != 0
    }
}

/// The generous L0 policy size cap applied to every (channel, direction) that
/// is NOT known to carry only small, fixed messages.
///
/// This equals the relay's absolute [`MAX_MESSAGE_SIZE`](crate::relay) resource
/// guard on purpose: the bulk directions (display server especially, which
/// carries image/surface payloads) have no meaningful per-message policy cap
/// below the absolute guard *yet*. It is deliberately conservative to avoid
/// false positives before the step-4f capture validation observes real peak
/// sizes and tightens it. Until then the absolute guard is the effective bound
/// for these directions, and the `size_cap` rule only fires on the tight
/// directions below.
const GENEROUS_SIZE_CAP: u32 = 16 * 1024 * 1024;

/// The tight L0 policy size cap for the input-event client directions
/// (inputs-client and cursor-client). Key and mouse events are well-modeled,
/// fixed, and tiny (tens of bytes); 4 KiB is generous headroom over any
/// legitimate one while still refusing an absurd body long before the absolute
/// guard. Validated/tuned by step 4f.
const INPUT_CLIENT_SIZE_CAP: u32 = 4 * 1024;

/// A coarse per-direction rate/throughput ceiling.
///
/// DISABLED by default (`FirewallPolicy::rate_limit == None`): picking real
/// values needs the step-4f captures, and a wrong default would false-positive
/// on legitimate bursts (e.g. a display refresh storm). The mechanism ships so
/// a deployment can opt in once tuned; the counter is a simple fixed window
/// per relay direction (see [`EnforcingPolicy`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RateLimit {
    /// Maximum framed messages permitted within `window`.
    pub max_messages: u64,
    /// Maximum bytes (header + body) permitted within `window`.
    pub max_bytes: u64,
    /// The length of the fixed accounting window.
    pub window: Duration,
}

/// The tunable firewall knobs for one connection, delivered per-connection.
///
/// Shared across the two relay directions as an `Arc<FirewallPolicy>` so the
/// allowlist lookup and cap checks need no lock on the hot path (phase-4 plan,
/// Design decision 2). This holds only the deployment-tunable knobs; the L1
/// allowlist tables themselves are a compiled-in fact about the SPICE protocol
/// (`allowlist.rs`), not policy.
///
/// `Default` is **enforcing** and permits ALL known channel types. The L0 size
/// caps are conservative (generous everywhere except the tiny input-event
/// client directions) and the rate limit is OFF, so the default cannot
/// false-positive on legitimate traffic before step 4f validates it.
#[derive(Clone, Debug)]
pub struct FirewallPolicy {
    /// Whether blocking verdicts are applied or merely observed.
    pub mode: EnforcementMode,
    /// The verdict for an L1 grammar violation (disallowed message type) on a
    /// MODELED channel. Defaults to [`Verdict::Terminate`] (fail closed).
    pub disallowed_type_verdict: Verdict,
    /// The verdict for an L0 size-cap violation. Defaults to
    /// [`Verdict::Terminate`] (fail closed).
    pub size_cap_verdict: Verdict,
    /// The verdict for an L0 rate-ceiling violation. Defaults to
    /// [`Verdict::Terminate`]; only consulted when `rate_limit` is `Some`.
    pub rate_verdict: Verdict,
    /// The per-direction rate/throughput ceiling, or `None` to disable rate
    /// accounting entirely (the default — see [`RateLimit`]).
    pub rate_limit: Option<RateLimit>,
    /// Which channel types may be relayed. Consulted via
    /// [`FirewallPolicy::channel_permitted`] by the pre-relay channel gate in
    /// `session.rs`.
    permitted_channels: PermittedChannels,
}

impl Default for FirewallPolicy {
    fn default() -> Self {
        FirewallPolicy {
            mode: EnforcementMode::Enforce,
            disallowed_type_verdict: Verdict::Terminate,
            size_cap_verdict: Verdict::Terminate,
            rate_verdict: Verdict::Terminate,
            rate_limit: None,
            permitted_channels: PermittedChannels::all(),
        }
    }
}

impl FirewallPolicy {
    /// Build the connection's policy from the `FirewallPolicy` delivered in the
    /// gRPC `AuthorizeConnection` reply (step 4e).
    ///
    /// Maps the two deployment-tunable knobs Python delivers — the enforcement
    /// `mode` and the `permitted_channels` set — onto a policy whose OTHER
    /// fields (size caps, rate limit, per-verdict severities) stay at their
    /// enforcing compiled [`Default`]s (they have no gRPC config surface in v1).
    /// An empty `permitted_channels` means "permit all" (see
    /// [`PermittedChannels::from_discriminants`]).
    pub fn from_proto(proto: crate::pb::FirewallPolicy) -> Self {
        let mode = match proto.mode() {
            crate::pb::firewall_policy::Mode::Enforce => EnforcementMode::Enforce,
            crate::pb::firewall_policy::Mode::WarnOnly => EnforcementMode::WarnOnly,
        };
        FirewallPolicy {
            mode,
            permitted_channels: PermittedChannels::from_discriminants(&proto.permitted_channels),
            ..FirewallPolicy::default()
        }
    }

    /// Whether `ch` may be relayed under this policy.
    ///
    /// Consulted by the pre-relay channel gate in `session.rs`: a forbidden
    /// channel is denied (`PermissionDenied`) before any relay. The default
    /// permits every channel, so with the default config this never fires.
    pub fn channel_permitted(&self, ch: ChannelType) -> bool {
        self.permitted_channels.contains(ch)
    }

    /// The L0 policy size cap for one (channel, direction), in body bytes.
    ///
    /// This is a POLICY cap, distinct from and (for the tight directions) below
    /// the relay's absolute [`MAX_MESSAGE_SIZE`](crate::relay) resource guard.
    /// Tight only where the messages are known-small and fixed — the
    /// input-event client directions (inputs-client, cursor-client key/mouse
    /// events). Everything else (the display server bulk direction especially,
    /// and any unmodeled channel) stays generous. Step 4f validates these
    /// against real captures and tightens the generous default.
    pub fn max_message_size(&self, channel: ChannelType, dir: Direction) -> u32 {
        match (channel, dir) {
            (ChannelType::Inputs, Direction::ClientToServer)
            | (ChannelType::Cursor, Direction::ClientToServer) => INPUT_CLIENT_SIZE_CAP,
            _ => GENEROUS_SIZE_CAP,
        }
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
#[derive(Debug)]
pub struct VerdictTally {
    /// One atomic per `(rule, action)` pair, indexed by
    /// [`VerdictTally::slot`]. An array (rather than named fields) so adding a
    /// rule is one enum arm plus a bump of [`RULE_COUNT`], with no per-field
    /// churn here.
    counters: [AtomicU64; RULE_COUNT * ACTION_COUNT],
}

impl Default for VerdictTally {
    fn default() -> Self {
        VerdictTally {
            counters: std::array::from_fn(|_| AtomicU64::new(0)),
        }
    }
}

impl VerdictTally {
    /// A fresh, empty tally.
    pub fn new() -> Self {
        Self::default()
    }

    /// The dense counter index for one `(rule, action)` pair.
    fn slot(rule: Rule, action: Action) -> usize {
        rule.index() * ACTION_COUNT + action.index()
    }

    /// Increment the counter for one `(rule, action)` verdict. Lock-free;
    /// called only on the cold violation path, never for `Allowed`.
    fn record(&self, rule: Rule, action: Action) {
        self.counters[Self::slot(rule, action)].fetch_add(1, Ordering::Relaxed);
    }

    /// The current count for one `(rule, action)` verdict.
    fn count(&self, rule: Rule, action: Action) -> u64 {
        self.counters[Self::slot(rule, action)].load(Ordering::Relaxed)
    }

    /// Format a single summary line describing every verdict recorded on this
    /// connection, or `None` if nothing was recorded (so the caller sends no
    /// audit event). Carries only channel-agnostic rule/action counts — no
    /// ticket or token.
    pub fn summary(&self) -> Option<String> {
        let mut parts = Vec::new();
        for rule in Rule::all() {
            let enforced = self.count(rule, Action::Enforced);
            let observed = self.count(rule, Action::Observed);
            if enforced + observed > 0 {
                parts.push(format!(
                    "{} (enforced={enforced}, observed={observed})",
                    rule.label()
                ));
            }
        }
        if parts.is_empty() {
            return None;
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
    /// Start of the current rate-accounting window, or `None` until the first
    /// message. Per-direction state; touched only when `policy.rate_limit` is
    /// `Some`. `&mut self` on the trait methods lets this live inline (no lock).
    rate_window_start: Option<Instant>,
    /// Framed messages seen in the current window.
    rate_messages: u64,
    /// Bytes (header + body) seen in the current window.
    rate_bytes: u64,
}

impl EnforcingPolicy {
    /// Build the enforcing policy for one direction, sharing the connection's
    /// config and verdict tally.
    pub fn new(policy: Arc<FirewallPolicy>, dir: Direction, tally: Arc<VerdictTally>) -> Self {
        EnforcingPolicy {
            policy,
            dir,
            tally,
            rate_window_start: None,
            rate_messages: 0,
            rate_bytes: 0,
        }
    }

    /// Account for one framed message against `limit` and report whether the
    /// current fixed window has now exceeded it. Resets the window when it has
    /// elapsed. Called once per message (the relay de-duplicates header checks
    /// across partial reads), only when a rate limit is configured.
    fn rate_exceeds(&mut self, limit: RateLimit, message_size: u32) -> bool {
        let now = Instant::now();
        let start = match self.rate_window_start {
            Some(start) => start,
            None => {
                self.rate_window_start = Some(now);
                now
            }
        };
        if now.duration_since(start) >= limit.window {
            self.rate_window_start = Some(now);
            self.rate_messages = 0;
            self.rate_bytes = 0;
        }
        self.rate_messages += 1;
        self.rate_bytes += MessageHeader::SIZE as u64 + message_size as u64;
        self.rate_messages > limit.max_messages || self.rate_bytes > limit.max_bytes
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

    fn check_header(
        &mut self,
        dir: Direction,
        channel: ChannelType,
        header: &MessageHeader,
    ) -> Verdict {
        // One EnforcingPolicy serves one direction; the relay passes the
        // matching direction. Recording uses `self.dir`.
        debug_assert_eq!(dir, self.dir);

        // L0 size cap: the policy cap sits below the relay's absolute resource
        // guard, so this refuses an oversized body before the relay buffers it.
        // In WarnOnly, `apply` returns Forward and the relay buffers the body
        // anyway (still bounded by the absolute guard).
        if header.message_size > self.policy.max_message_size(channel, dir) {
            return self.apply(Rule::SizeCap, channel, self.policy.size_cap_verdict);
        }

        // L0 rate/throughput ceiling: disabled unless a limit is configured.
        // `RateLimit` is Copy, so this borrows nothing from `self.policy` while
        // `rate_exceeds` takes `&mut self`.
        if let Some(limit) = self.policy.rate_limit {
            if self.rate_exceeds(limit, header.message_size) {
                return self.apply(Rule::RateCap, channel, self.policy.rate_verdict);
            }
        }

        Verdict::Forward
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
    fn from_proto_maps_mode_and_permitted_channels() {
        let fp = FirewallPolicy::from_proto(crate::pb::FirewallPolicy {
            mode: crate::pb::firewall_policy::Mode::WarnOnly as i32,
            permitted_channels: vec![1, 3], // main, inputs
        });
        assert_eq!(fp.mode, EnforcementMode::WarnOnly);
        assert!(fp.channel_permitted(ChannelType::Main));
        assert!(fp.channel_permitted(ChannelType::Inputs));
        assert!(!fp.channel_permitted(ChannelType::Display));
    }

    #[test]
    fn from_proto_empty_permitted_channels_means_all() {
        let fp = FirewallPolicy::from_proto(crate::pb::FirewallPolicy {
            mode: crate::pb::firewall_policy::Mode::Enforce as i32,
            permitted_channels: vec![],
        });
        assert_eq!(fp.mode, EnforcementMode::Enforce);
        for ch in ALL_CHANNELS {
            assert!(fp.channel_permitted(ch), "empty list must permit {ch:?}");
        }
    }

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
        assert_eq!(tally.count(Rule::DisallowedType, Action::Enforced), 1);
        assert_eq!(tally.count(Rule::DisallowedType, Action::Observed), 0);
    }

    #[test]
    fn enforce_unmodeled_forwards_and_records_observed() {
        let (mut engine, tally) = inputs_policy(EnforcementMode::Enforce);
        // Record is an unmodeled channel: even in Enforce, observe-only.
        assert_eq!(
            inspect(&mut engine, ChannelType::Record, DISALLOWED_TYPE),
            Verdict::Forward
        );
        assert_eq!(tally.count(Rule::UnmodeledType, Action::Observed), 1);
        assert_eq!(tally.count(Rule::UnmodeledType, Action::Enforced), 0);
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
        assert_eq!(tally.count(Rule::DisallowedType, Action::Observed), 1);
        assert_eq!(tally.count(Rule::DisallowedType, Action::Enforced), 0);
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

        assert_eq!(tally.count(Rule::DisallowedType, Action::Enforced), 2);
        assert_eq!(tally.count(Rule::DisallowedType, Action::Observed), 0);
        assert_eq!(tally.count(Rule::UnmodeledType, Action::Observed), 1);
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

        assert_eq!(tally.count(Rule::DisallowedType, Action::Enforced), 2);
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

    #[test]
    fn summary_mentions_size_and_rate_caps() {
        let tally = VerdictTally::new();
        tally.record(Rule::SizeCap, Action::Enforced);
        tally.record(Rule::RateCap, Action::Observed);

        let summary = tally.summary().expect("non-empty tally has a summary");
        assert!(summary.contains("size_cap"), "summary: {summary}");
        assert!(summary.contains("rate_cap"), "summary: {summary}");
    }

    // --- L0 size cap (check_header). ---

    /// A body size over the tight inputs-client policy cap but well under the
    /// relay's absolute 16 MiB resource guard.
    const OVER_POLICY_CAP_UNDER_ABSOLUTE: u32 = INPUT_CLIENT_SIZE_CAP + 1;

    fn sized_header(message_size: u32) -> MessageHeader {
        MessageHeader {
            message_type: ALLOWED_TYPE,
            message_size,
        }
    }

    fn check_header(engine: &mut EnforcingPolicy, ch: ChannelType, size: u32) -> Verdict {
        engine.check_header(Direction::ClientToServer, ch, &sized_header(size))
    }

    #[test]
    fn enforce_oversized_for_policy_cap_terminates_and_records_size_cap() {
        let (mut engine, tally) = inputs_policy(EnforcementMode::Enforce);
        assert_eq!(
            check_header(
                &mut engine,
                ChannelType::Inputs,
                OVER_POLICY_CAP_UNDER_ABSOLUTE
            ),
            Verdict::Terminate
        );
        assert_eq!(tally.count(Rule::SizeCap, Action::Enforced), 1);
        assert_eq!(tally.count(Rule::SizeCap, Action::Observed), 0);
    }

    #[test]
    fn warn_only_oversized_for_policy_cap_forwards_and_records_observed() {
        let (mut engine, tally) = inputs_policy(EnforcementMode::WarnOnly);
        assert_eq!(
            check_header(
                &mut engine,
                ChannelType::Inputs,
                OVER_POLICY_CAP_UNDER_ABSOLUTE
            ),
            Verdict::Forward
        );
        assert_eq!(tally.count(Rule::SizeCap, Action::Observed), 1);
        assert_eq!(tally.count(Rule::SizeCap, Action::Enforced), 0);
    }

    #[test]
    fn within_policy_cap_forwards_without_recording() {
        let (mut engine, tally) = inputs_policy(EnforcementMode::Enforce);
        assert_eq!(
            check_header(&mut engine, ChannelType::Inputs, INPUT_CLIENT_SIZE_CAP),
            Verdict::Forward
        );
        assert!(tally.summary().is_none(), "within-cap must not be recorded");
    }

    #[test]
    fn generous_channel_does_not_trip_the_tight_cap() {
        // A body that would trip the tight inputs cap is fine on display, which
        // uses the generous cap (the absolute relay guard is the real bound).
        let (mut engine, tally) = inputs_policy(EnforcementMode::Enforce);
        assert_eq!(
            check_header(
                &mut engine,
                ChannelType::Display,
                OVER_POLICY_CAP_UNDER_ABSOLUTE
            ),
            Verdict::Forward
        );
        assert!(tally.summary().is_none());
    }

    // --- L0 rate ceiling. ---

    #[test]
    fn rate_limit_disabled_by_default_never_trips() {
        let (mut engine, tally) = inputs_policy(EnforcementMode::Enforce);
        assert!(engine.policy.rate_limit.is_none(), "default disables rate");
        for _ in 0..1000 {
            assert_eq!(
                check_header(&mut engine, ChannelType::Inputs, 8),
                Verdict::Forward
            );
        }
        assert!(tally.summary().is_none());
    }

    #[test]
    fn rate_limit_trips_when_message_count_exceeded() {
        let policy = Arc::new(FirewallPolicy {
            rate_limit: Some(RateLimit {
                max_messages: 2,
                max_bytes: u64::MAX,
                // A long window so the three messages fall inside it.
                window: Duration::from_secs(3600),
            }),
            ..FirewallPolicy::default()
        });
        let tally = Arc::new(VerdictTally::new());
        let mut engine =
            EnforcingPolicy::new(policy, Direction::ClientToServer, Arc::clone(&tally));

        // First two are within the message allowance.
        assert_eq!(
            check_header(&mut engine, ChannelType::Inputs, 8),
            Verdict::Forward
        );
        assert_eq!(
            check_header(&mut engine, ChannelType::Inputs, 8),
            Verdict::Forward
        );
        // The third exceeds max_messages.
        assert_eq!(
            check_header(&mut engine, ChannelType::Inputs, 8),
            Verdict::Terminate
        );
        assert_eq!(tally.count(Rule::RateCap, Action::Enforced), 1);
    }

    #[test]
    fn rate_limit_trips_when_byte_ceiling_exceeded() {
        let policy = Arc::new(FirewallPolicy {
            rate_limit: Some(RateLimit {
                max_messages: u64::MAX,
                max_bytes: 100,
                window: Duration::from_secs(3600),
            }),
            ..FirewallPolicy::default()
        });
        let tally = Arc::new(VerdictTally::new());
        let mut engine =
            EnforcingPolicy::new(policy, Direction::ClientToServer, Arc::clone(&tally));

        // 6-byte header + 90-byte body = 96 bytes < 100: within the ceiling.
        assert_eq!(
            check_header(&mut engine, ChannelType::Inputs, 90),
            Verdict::Forward
        );
        // Another 96 bytes pushes the window total to 192 > 100.
        assert_eq!(
            check_header(&mut engine, ChannelType::Inputs, 90),
            Verdict::Terminate
        );
        assert_eq!(tally.count(Rule::RateCap, Action::Enforced), 1);
    }
}
