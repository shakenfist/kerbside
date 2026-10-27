//! Observation of spice-server's per-channel ACK window from the relay.
//!
//! spice-server flow-controls its display and cursor channels in messages,
//! not bytes (`server/red-channel-client.cpp` in spice):
//!
//! - It sends `SET_ACK { generation, window }`. Sending it bumps the
//!   generation and resets the server's count of unacknowledged messages
//!   (`messages_window`) to zero; the `SET_ACK` itself is then counted like
//!   any other message, so the count is 1 once it has gone.
//! - Every message the server sends adds one to `messages_window`.
//! - The client answers `SET_ACK` with `ACK_SYNC { generation }`, and the
//!   server remembers that as the client's generation.
//! - The client then sends a bodiless `ACK` after every `window` messages it
//!   receives. The server subtracts `window` from `messages_window` for each
//!   `ACK`, but only while the client's generation matches its own, so `ACK`s
//!   sent before the client has synced to a new `SET_ACK` are ignored.
//! - The server sends nothing more while `messages_window > 2 * window`
//!   (`waiting_for_ack`). It can therefore have at most `2 * window + 1`
//!   messages unacknowledged, however small they are.
//!
//! The window is 20 messages, or 40 when the main channel's start-up
//! bandwidth test judged the client's link to be slow (`dcc.h`,
//! `common-graphics-channel.cpp`).
//!
//! Kerbside relays every message involved, so it can follow the server's
//! count. [`AckTracker`] is that bookkeeping, kept pure so it can be tested
//! with explicit timestamps; [`AckObserver`] wraps it for the relay's two
//! pumps and exports what it sees as Prometheus metrics. Neither ever changes
//! a byte that is forwarded.
//!
//! The relay's count lags the server's. spice-server counts a message when it
//! hands it to its socket; the relay counts it when it has read the whole
//! message. Messages still in qemu's socket send buffer, in the proxy's
//! backend receive buffer, or part-read are counted by the server but not yet
//! by the relay. The relay's in-flight count is therefore a lower bound on
//! the server's, and exact only when the backend leg holds no backlog. The
//! client's `ACK`s cross the backend leg's loopback in the other direction,
//! so the relay sees them at about the moment the server does.

use std::sync::Mutex;
use std::time::{Duration, Instant};

// SET_ACK, ACK_SYNC and ACK are base-channel messages with the same opcodes
// on every channel, so the display constants serve the cursor channel too.
use shakenfist_spice_protocol::constants::{display_client, display_server};
use shakenfist_spice_protocol::messages::{AckSync, SetAck, WireType};
use shakenfist_spice_protocol::ChannelType;
use tracing::{debug, info};

/// What one message did to the tracker, for the caller to export.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Observation {
    /// A `SET_ACK` was seen (its generation and window).
    pub set_ack: Option<(u32, u32)>,
    /// An `ACK_SYNC` was seen (its generation).
    pub ack_sync: Option<u32>,
    /// A server message was counted against the window.
    pub counted: bool,
    /// A client `ACK` was credited (its generation matched).
    pub acked: bool,
    /// This message took the in-flight count to the block threshold.
    pub stall_started: bool,
    /// Time spent at the block threshold since the previous message.
    pub stalled_for: Duration,
}

/// The relay's copy of spice-server's ACK-window state for one channel.
#[derive(Debug)]
pub struct AckTracker {
    /// The generation of the latest `SET_ACK`, or `None` before the first.
    generation: Option<u32>,
    /// The window of the latest `SET_ACK`.
    window: u32,
    /// The generation of the latest `ACK_SYNC`, or `None` before the first.
    client_generation: Option<u32>,
    /// spice-server's `messages_window`: messages sent since the latest
    /// `SET_ACK` (counting it), less `window` for each credited `ACK`.
    /// Signed, so a client that acknowledges more than it received shows as
    /// a negative count rather than wrapping as the server's `uint32_t` does.
    in_flight: i64,
    /// When the in-flight count last reached the threshold, while it is
    /// still there.
    stalled_since: Option<Instant>,
    /// The last time stalled time was handed to the caller.
    stalled_mark: Option<Instant>,

    // Totals for the end-of-relay summary.
    set_acks: u64,
    messages: u64,
    acks: u64,
    ignored_acks: u64,
    stalls: u64,
    stalled_total: Duration,
    max_in_flight: i64,
}

impl Default for AckTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl AckTracker {
    pub fn new() -> Self {
        Self {
            generation: None,
            window: 0,
            client_generation: None,
            in_flight: 0,
            stalled_since: None,
            stalled_mark: None,
            set_acks: 0,
            messages: 0,
            acks: 0,
            ignored_acks: 0,
            stalls: 0,
            stalled_total: Duration::ZERO,
            max_in_flight: 0,
        }
    }

    /// The window of the latest `SET_ACK`, or `None` before the first.
    pub fn window(&self) -> Option<u32> {
        self.generation.map(|_| self.window)
    }

    /// The generation of the latest `SET_ACK`, or `None` before the first.
    pub fn generation(&self) -> Option<u32> {
        self.generation
    }

    /// The in-flight count, or `None` before the first `SET_ACK`.
    pub fn in_flight(&self) -> Option<i64> {
        self.generation.map(|_| self.in_flight)
    }

    /// The count above which spice-server stops sending: twice the window.
    fn threshold(&self) -> i64 {
        2 * i64::from(self.window)
    }

    /// Whether the in-flight count is past the threshold, which is where
    /// spice-server waits for an `ACK` before sending again.
    pub fn is_stalled(&self) -> bool {
        self.generation.is_some() && self.in_flight > self.threshold()
    }

    /// Hand over the stalled time accrued since the last hand-over.
    fn take_stalled(&mut self, now: Instant) -> Duration {
        match self.stalled_mark {
            Some(mark) => {
                let d = now.saturating_duration_since(mark);
                self.stalled_mark = Some(now);
                self.stalled_total += d;
                d
            }
            None => Duration::ZERO,
        }
    }

    /// Re-evaluate the threshold after a change to the count.
    fn settle(&mut self, now: Instant, obs: &mut Observation) {
        self.max_in_flight = self.max_in_flight.max(self.in_flight);
        let stalled = self.is_stalled();
        match (self.stalled_since.is_some(), stalled) {
            (false, true) => {
                self.stalled_since = Some(now);
                self.stalled_mark = Some(now);
                self.stalls += 1;
                obs.stall_started = true;
            }
            (true, false) => {
                self.stalled_since = None;
                self.stalled_mark = None;
            }
            _ => {}
        }
    }

    /// Account for one complete server-to-client message.
    pub fn on_server_message(
        &mut self,
        message_type: u16,
        body: &[u8],
        now: Instant,
    ) -> Observation {
        let mut obs = Observation {
            stalled_for: self.take_stalled(now),
            ..Observation::default()
        };
        if message_type == display_server::SET_ACK {
            match SetAck::decode(body) {
                Ok(set_ack) => {
                    self.generation = Some(set_ack.generation);
                    self.window = set_ack.window;
                    self.in_flight = 1;
                    self.set_acks += 1;
                    self.messages += 1;
                    obs.set_ack = Some((set_ack.generation, set_ack.window));
                    obs.counted = true;
                }
                Err(_) => {
                    // A server that sends a malformed SET_ACK has broken the
                    // channel for the client too; leave the count alone.
                }
            }
        } else if self.generation.is_some() {
            self.in_flight += 1;
            self.messages += 1;
            obs.counted = true;
        }
        self.settle(now, &mut obs);
        obs
    }

    /// Account for one client-to-server message the relay forwarded.
    pub fn on_client_message(
        &mut self,
        message_type: u16,
        body: &[u8],
        now: Instant,
    ) -> Observation {
        let mut obs = Observation {
            stalled_for: self.take_stalled(now),
            ..Observation::default()
        };
        if message_type == display_client::ACK_SYNC {
            if let Ok(sync) = AckSync::decode(body) {
                self.client_generation = Some(sync.generation);
                obs.ack_sync = Some(sync.generation);
            }
        } else if message_type == display_client::ACK {
            if self.generation.is_some() && self.client_generation == self.generation {
                self.in_flight -= i64::from(self.window);
                self.acks += 1;
                obs.acked = true;
            } else {
                self.ignored_acks += 1;
            }
        }
        self.settle(now, &mut obs);
        obs
    }

    /// Hand over any stalled time still accruing, at the end of the relay.
    pub fn finish(&mut self, now: Instant) -> Duration {
        self.take_stalled(now)
    }
}

/// Whether spice-server applies its ACK window to this channel type. Only
/// display and cursor channels are created with `RedChannel::HandleAcks`.
pub fn tracks(channel: ChannelType) -> bool {
    matches!(channel, ChannelType::Display | ChannelType::Cursor)
}

/// An [`AckTracker`] shared by one relayed channel's two pumps, exporting
/// what it observes as metrics.
pub struct AckObserver {
    channel: &'static str,
    tracker: Mutex<AckTracker>,
}

impl AckObserver {
    /// An observer for `channel`, or `None` if spice-server does not apply
    /// an ACK window to that channel type.
    pub fn for_channel(channel: ChannelType) -> Option<Self> {
        tracks(channel).then(|| Self {
            channel: channel.name(),
            tracker: Mutex::new(AckTracker::new()),
        })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, AckTracker> {
        // The tracker holds plain counters, so a panic elsewhere cannot leave
        // it inconsistent enough to matter; carry on with what is there.
        self.tracker.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Observe one complete server-to-client message.
    pub fn server_message(&self, message_type: u16, body: &[u8], connection_ref: &str) {
        let obs = self
            .lock()
            .on_server_message(message_type, body, Instant::now());
        self.export(&obs, connection_ref);
    }

    /// Observe one client-to-server message that was forwarded.
    pub fn client_message(&self, message_type: u16, body: &[u8], connection_ref: &str) {
        let obs = self
            .lock()
            .on_client_message(message_type, body, Instant::now());
        self.export(&obs, connection_ref);
    }

    fn export(&self, obs: &Observation, connection_ref: &str) {
        if let Some((generation, window)) = obs.set_ack {
            crate::metrics::record_ack_window_set(self.channel, window);
            debug!(%connection_ref, channel = self.channel, generation, window, "SET_ACK observed");
        }
        if let Some(generation) = obs.ack_sync {
            debug!(%connection_ref, channel = self.channel, generation, "ACK_SYNC observed");
        }
        if obs.counted {
            crate::metrics::inc_ack_window_messages(self.channel);
        }
        if obs.acked {
            crate::metrics::inc_ack_window_acks(self.channel);
        }
        if obs.stall_started {
            crate::metrics::inc_ack_window_stalls(self.channel);
        }
        if !obs.stalled_for.is_zero() {
            crate::metrics::add_ack_window_stalled(self.channel, obs.stalled_for);
        }
    }

    /// Flush stalled time still accruing and log a one-line summary of the
    /// channel's ACK window. Called once, when the relay ends.
    pub fn finish(&self, connection_ref: &str) {
        let mut t = self.lock();
        let stalled_for = t.finish(Instant::now());
        if !stalled_for.is_zero() {
            crate::metrics::add_ack_window_stalled(self.channel, stalled_for);
        }
        if t.set_acks == 0 {
            return;
        }
        info!(
            %connection_ref,
            channel = self.channel,
            generation = t.generation().unwrap_or_default(),
            window = t.window().unwrap_or_default(),
            in_flight = t.in_flight().unwrap_or_default(),
            set_acks = t.set_acks,
            messages = t.messages,
            acks = t.acks,
            ignored_acks = t.ignored_acks,
            stalls = t.stalls,
            stalled_ms = t.stalled_total.as_millis() as u64,
            max_in_flight = t.max_in_flight,
            "ACK window summary"
        );
    }

    /// A copy of the tracker's counts, for tests.
    #[cfg(test)]
    pub fn snapshot(&self) -> (Option<u32>, Option<u32>, Option<i64>, u64, u64) {
        let t = self.lock();
        (
            t.generation(),
            t.window(),
            t.in_flight(),
            t.messages,
            t.acks,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set_ack(generation: u32, window: u32) -> Vec<u8> {
        let mut body = Vec::new();
        SetAck { generation, window }.write(&mut body);
        body
    }

    fn ack_sync(generation: u32) -> Vec<u8> {
        let mut body = Vec::new();
        AckSync { generation }.write(&mut body);
        body
    }

    /// An arbitrary display message that is not SET_ACK (DRAW_COPY).
    const DRAW: u16 = 304;

    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    #[test]
    fn nothing_is_counted_before_set_ack() {
        let t0 = Instant::now();
        let mut t = AckTracker::new();
        let obs = t.on_server_message(DRAW, b"x", t0);
        assert!(!obs.counted);
        assert_eq!(t.in_flight(), None);
        assert_eq!(t.window(), None);
        // An ACK before any SET_ACK is ignored, as the server ignores one
        // whose generation does not match.
        let obs = t.on_client_message(display_client::ACK, b"", t0);
        assert!(!obs.acked);
        assert!(!t.is_stalled());
    }

    #[test]
    fn set_ack_counts_itself_and_records_the_window() {
        let t0 = Instant::now();
        let mut t = AckTracker::new();
        let obs = t.on_server_message(display_server::SET_ACK, &set_ack(1, 20), t0);
        assert_eq!(obs.set_ack, Some((1, 20)));
        assert!(obs.counted);
        assert_eq!(t.generation(), Some(1));
        assert_eq!(t.window(), Some(20));
        assert_eq!(t.in_flight(), Some(1));
    }

    #[test]
    fn stalls_past_twice_the_window_and_an_ack_releases() {
        let t0 = Instant::now();
        let mut t = AckTracker::new();
        t.on_server_message(display_server::SET_ACK, &set_ack(1, 20), t0);
        t.on_client_message(display_client::ACK_SYNC, &ack_sync(1), t0);
        // SET_ACK plus 39 messages: 40 in flight, which the server still
        // sends past.
        for _ in 0..39 {
            let obs = t.on_server_message(DRAW, b"x", t0);
            assert!(obs.counted);
            assert!(!obs.stall_started);
        }
        assert_eq!(t.in_flight(), Some(40));
        assert!(!t.is_stalled());
        // The 41st (2W + 1) is the last the server sends before waiting.
        let obs = t.on_server_message(DRAW, b"x", t0);
        assert!(obs.stall_started);
        assert!(t.is_stalled());
        assert_eq!(t.in_flight(), Some(41));

        // An ACK 30 ms later credits one window and ends the stall, handing
        // over the 30 ms spent at the threshold.
        let obs = t.on_client_message(display_client::ACK, b"", t0 + ms(30));
        assert!(obs.acked);
        assert_eq!(obs.stalled_for, ms(30));
        assert_eq!(t.in_flight(), Some(21));
        assert!(!t.is_stalled());
        assert_eq!(t.stalls, 1);
        assert_eq!(t.stalled_total, ms(30));
        assert_eq!(t.max_in_flight, 41);
    }

    #[test]
    fn stalled_time_is_handed_over_at_each_message_and_at_finish() {
        let t0 = Instant::now();
        let mut t = AckTracker::new();
        t.on_server_message(display_server::SET_ACK, &set_ack(1, 1), t0);
        t.on_server_message(DRAW, b"x", t0);
        let obs = t.on_server_message(DRAW, b"x", t0);
        assert!(obs.stall_started);
        // Unrelated client traffic while stalled hands over the time so far.
        let obs = t.on_client_message(101, b"", t0 + ms(10));
        assert_eq!(obs.stalled_for, ms(10));
        assert!(t.is_stalled());
        assert_eq!(t.finish(t0 + ms(25)), ms(15));
        assert_eq!(t.stalled_total, ms(25));
        // Nothing accrues twice.
        assert_eq!(t.finish(t0 + ms(25)), Duration::ZERO);
    }

    #[test]
    fn acks_before_ack_sync_are_ignored() {
        let t0 = Instant::now();
        let mut t = AckTracker::new();
        t.on_server_message(display_server::SET_ACK, &set_ack(7, 20), t0);
        for _ in 0..20 {
            t.on_server_message(DRAW, b"x", t0);
        }
        let obs = t.on_client_message(display_client::ACK, b"", t0);
        assert!(!obs.acked);
        assert_eq!(t.in_flight(), Some(21));
        assert_eq!(t.ignored_acks, 1);

        let obs = t.on_client_message(display_client::ACK_SYNC, &ack_sync(7), t0);
        assert_eq!(obs.ack_sync, Some(7));
        let obs = t.on_client_message(display_client::ACK, b"", t0);
        assert!(obs.acked);
        assert_eq!(t.in_flight(), Some(1));
    }

    #[test]
    fn a_new_generation_resets_the_count_and_waits_for_its_ack_sync() {
        let t0 = Instant::now();
        let mut t = AckTracker::new();
        t.on_server_message(display_server::SET_ACK, &set_ack(1, 20), t0);
        t.on_client_message(display_client::ACK_SYNC, &ack_sync(1), t0);
        for _ in 0..40 {
            t.on_server_message(DRAW, b"x", t0);
        }
        assert!(t.is_stalled());

        // A new SET_ACK, with a wider window: the count restarts at 1 (the
        // SET_ACK itself) and the stall ends.
        let obs = t.on_server_message(display_server::SET_ACK, &set_ack(2, 40), t0 + ms(5));
        assert_eq!(obs.set_ack, Some((2, 40)));
        assert_eq!(obs.stalled_for, ms(5));
        assert_eq!(t.generation(), Some(2));
        assert_eq!(t.window(), Some(40));
        assert_eq!(t.in_flight(), Some(1));
        assert!(!t.is_stalled());

        for _ in 0..40 {
            t.on_server_message(DRAW, b"x", t0);
        }
        // An ACK still in flight from the old generation is not credited.
        let obs = t.on_client_message(display_client::ACK, b"", t0);
        assert!(!obs.acked);
        assert_eq!(t.in_flight(), Some(41));

        // Once the client syncs to generation 2, ACKs credit 40 at a time.
        t.on_client_message(display_client::ACK_SYNC, &ack_sync(2), t0);
        let obs = t.on_client_message(display_client::ACK, b"", t0);
        assert!(obs.acked);
        assert_eq!(t.in_flight(), Some(1));
        assert_eq!(t.set_acks, 2);
    }

    #[test]
    fn a_stale_ack_sync_does_not_credit_acks() {
        let t0 = Instant::now();
        let mut t = AckTracker::new();
        t.on_server_message(display_server::SET_ACK, &set_ack(3, 20), t0);
        t.on_client_message(display_client::ACK_SYNC, &ack_sync(2), t0);
        let obs = t.on_client_message(display_client::ACK, b"", t0);
        assert!(!obs.acked);
        assert_eq!(t.in_flight(), Some(1));
    }

    #[test]
    fn a_malformed_set_ack_is_ignored() {
        let t0 = Instant::now();
        let mut t = AckTracker::new();
        let obs = t.on_server_message(display_server::SET_ACK, &[0u8; 3], t0);
        assert_eq!(obs, Observation::default());
        assert_eq!(t.generation(), None);
    }

    #[test]
    fn base_channel_opcodes_match_on_cursor() {
        use shakenfist_spice_protocol::constants::{cursor_client, cursor_server};
        assert_eq!(cursor_server::SET_ACK, display_server::SET_ACK);
        assert_eq!(cursor_client::ACK_SYNC, display_client::ACK_SYNC);
        assert_eq!(cursor_client::ACK, display_client::ACK);
    }

    #[test]
    fn only_display_and_cursor_are_tracked() {
        assert!(tracks(ChannelType::Display));
        assert!(tracks(ChannelType::Cursor));
        assert!(!tracks(ChannelType::Main));
        assert!(!tracks(ChannelType::Inputs));
        assert!(AckObserver::for_channel(ChannelType::Main).is_none());
    }
}
