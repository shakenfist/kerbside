//! When the transcoder may send: the pacing decision.
//!
//! The transcoder sends one frame at a time (a run of draws and a `MARK`),
//! and starts the next only once the writer has handed the last to the
//! kernel. While it waits, damage merges in the surface mirror, so a slow
//! client is sent the screen as it is when it can take more, never the
//! frames it missed. What else gates a frame depends on the mode:
//!
//! - [`PacingMode::Socket`], the default: nothing else. The client socket's
//!   `TCP_NOTSENT_LOWAT` makes the kernel refuse more bytes while that many
//!   are still unsent, so the writer only finishes a frame once the link
//!   has nearly drained the one before. No `SET_ACK` is sent, so the client
//!   never sends an `ACK` (spice-gtk starts counting only on `SET_ACK`).
//! - [`PacingMode::AckWindow`], a measurement option: SPICE's own flow
//!   control, as spice-server and andris do it. The transcoder sends
//!   `SET_ACK` with a window of `W` messages, and the client sends an `ACK`
//!   for every `W` it receives. Like spice-server
//!   (`red-channel-client.cpp`, `red_channel_client_waiting_for_ack`), a
//!   message may be sent while no more than `2W` are unacknowledged; a frame
//!   starts only then, and each message of a frame waits for room.
//!
//! [`AckWindow`] is the bookkeeping and [`Pacer`] shares it between the task
//! that reads the client (which sees the `ACK`s) and the writer (which
//! waits for room).

use std::sync::{Mutex, MutexGuard};

use tokio::sync::Notify;

/// How the transcoder paces what it sends the client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacingMode {
    /// One frame at a time, gated by the client socket's unsent bytes.
    Socket,
    /// SPICE's ACK window of this many messages, as spice-server uses.
    AckWindow(u32),
}

/// The generation the transcoder's one `SET_ACK` carries.
pub const ACK_GENERATION: u32 = 1;

/// Messages sent and acknowledged under an ACK window of `window`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AckWindow {
    window: u32,
    /// Messages sent less `window` for each `ACK` received, never below 0:
    /// spice-server's `messages_window`.
    unacked: u64,
}

impl AckWindow {
    /// A window of `window` messages, none sent yet. A window of 0 is taken
    /// as 1.
    pub fn new(window: u32) -> Self {
        Self {
            window: window.max(1),
            unacked: 0,
        }
    }

    /// The window, in messages.
    #[cfg(test)]
    pub fn window(&self) -> u32 {
        self.window
    }

    /// Whether another message may be sent: no more than twice the window
    /// is unacknowledged.
    pub fn has_room(&self) -> bool {
        self.unacked <= 2 * u64::from(self.window)
    }

    /// Count one message sent.
    pub fn sent(&mut self) {
        self.unacked += 1;
    }

    /// Count one `ACK` received, which acknowledges a window of messages.
    pub fn acked(&mut self) {
        self.unacked = self.unacked.saturating_sub(u64::from(self.window));
    }

    /// Messages sent and not yet acknowledged.
    #[cfg(test)]
    pub fn unacked(&self) -> u64 {
        self.unacked
    }
}

/// The pacing state one transcoding channel shares between its tasks.
#[derive(Debug)]
pub struct Pacer {
    /// The ACK window, in [`PacingMode::AckWindow`] only.
    window: Option<Mutex<AckWindow>>,
    /// Woken whenever an `ACK` arrives.
    room: Notify,
}

impl Pacer {
    pub fn new(mode: PacingMode) -> Self {
        let window = match mode {
            PacingMode::Socket => None,
            PacingMode::AckWindow(window) => Some(Mutex::new(AckWindow::new(window))),
        };
        Self {
            window,
            room: Notify::new(),
        }
    }

    /// Lock the ACK window. A panic while it was held leaves a plain count
    /// that is still usable, so poisoning is ignored rather than spread to
    /// the writer and the reader.
    fn lock(window: &Mutex<AckWindow>) -> MutexGuard<'_, AckWindow> {
        window.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Whether a new frame may start, given whether the writer has finished
    /// the last one.
    pub fn may_start_frame(&self, writer_idle: bool) -> bool {
        writer_idle && self.has_room()
    }

    /// Whether a message may be sent now. Always, without an ACK window.
    pub fn has_room(&self) -> bool {
        self.window
            .as_ref()
            .is_none_or(|w| Self::lock(w).has_room())
    }

    /// Count one message sent.
    pub fn sent(&self) {
        if let Some(window) = &self.window {
            Self::lock(window).sent();
        }
    }

    /// Count one `ACK` from the client, and wake a writer waiting for room.
    pub fn acked(&self) {
        if let Some(window) = &self.window {
            Self::lock(window).acked();
            self.room.notify_waiters();
        }
    }

    /// Wait until a message may be sent. Returns at once without an ACK
    /// window.
    pub async fn wait_for_room(&self) {
        loop {
            // Registered before the check, so an ACK between the check and
            // the await is not missed.
            let notified = self.room.notified();
            if self.has_room() {
                return;
            }
            notified.await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::time::Duration;

    #[test]
    fn the_window_allows_twice_its_size_plus_one() {
        // spice-server blocks once more than 2W messages are unacknowledged,
        // so 2W + 1 go out before the first ACK.
        let mut window = AckWindow::new(20);
        let mut sent = 0;
        while window.has_room() {
            window.sent();
            sent += 1;
        }
        assert_eq!(sent, 41);
        window.acked();
        assert!(window.has_room());
        assert_eq!(window.unacked(), 21);
    }

    #[test]
    fn acks_never_take_the_count_below_zero() {
        let mut window = AckWindow::new(10);
        window.sent();
        window.acked();
        window.acked();
        assert_eq!(window.unacked(), 0);
        assert!(AckWindow::new(0).window() == 1, "a window of 0 is 1");
    }

    #[test]
    fn socket_pacing_waits_only_for_the_writer() {
        let pacer = Pacer::new(PacingMode::Socket);
        assert!(pacer.may_start_frame(true));
        assert!(!pacer.may_start_frame(false));
        // Without a window, sending never runs out of room, and ACKs (which
        // a client never sends without SET_ACK) change nothing.
        for _ in 0..10_000 {
            pacer.sent();
        }
        pacer.acked();
        assert!(pacer.may_start_frame(true));
    }

    #[test]
    fn ack_pacing_waits_for_the_writer_and_the_window() {
        let pacer = Pacer::new(PacingMode::AckWindow(2));
        assert!(pacer.may_start_frame(true));
        assert!(!pacer.may_start_frame(false), "the writer is busy");
        for _ in 0..5 {
            pacer.sent();
        }
        assert!(
            !pacer.may_start_frame(true),
            "five unacknowledged of a window of two"
        );
        pacer.acked();
        assert!(pacer.may_start_frame(true));
    }

    #[tokio::test]
    async fn a_writer_waiting_for_room_wakes_on_an_ack() {
        let pacer = Arc::new(Pacer::new(PacingMode::AckWindow(1)));
        for _ in 0..3 {
            pacer.sent();
        }
        let waiter = {
            let pacer = Arc::clone(&pacer);
            tokio::spawn(async move { pacer.wait_for_room().await })
        };
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(!waiter.is_finished(), "no room until an ACK");
        pacer.acked();
        tokio::time::timeout(Duration::from_secs(5), waiter)
            .await
            .expect("the ACK wakes the writer")
            .expect("the waiter does not panic");
    }
}
