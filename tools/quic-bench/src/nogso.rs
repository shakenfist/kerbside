//! A UDP socket wrapper that refuses to use generic segmentation offload.
//!
//! Why this exists. The shaped link is a veth pair with a netem qdisc whose
//! queue limit is counted in packets, so netem has to see MTU-sized packets
//! for the queue depth -- and so the loss term -- to mean what it says.
//! Capping the device's GSO size works for TCP, where the device segments
//! after the qdisc. It does not work for UDP: a sender that sets UDP_SEGMENT
//! hands netem one super-packet per write whatever the device's GSO limits
//! say, so a queue of 110 slots holds ten times the bytes it should and a loss
//! term drops whole writes instead of single datagrams. That is not a link
//! anybody deploys, so the measurement would be meaningless.
//!
//! quinn consults `AsyncUdpSocket::max_transmit_segments()` to decide how many
//! datagrams to pack into one write, and there is no configuration setter for
//! it. The runtime's own socket delegates that method to quinn-udp's detected
//! GSO capability. Wrapping the runtime's socket in a newtype that returns 1
//! is therefore the whole of the fix: every other method delegates, so the
//! socket behaves exactly as it otherwise would and quinn simply never batches.

use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, UdpPoller};

/// Wraps an `AsyncUdpSocket`, reporting a single transmit segment.
pub struct NoGso {
    inner: Arc<dyn AsyncUdpSocket>,
}

impl NoGso {
    pub fn new(inner: Arc<dyn AsyncUdpSocket>) -> Self {
        Self { inner }
    }
}

impl fmt::Debug for NoGso {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NoGso").field("inner", &self.inner).finish()
    }
}

impl AsyncUdpSocket for NoGso {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        self.inner.clone().create_io_poller()
    }

    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        self.inner.try_send(transmit)
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [io::IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        self.inner.poll_recv(cx, bufs, meta)
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    /// The point of the newtype.
    fn max_transmit_segments(&self) -> usize {
        1
    }

    fn max_receive_segments(&self) -> usize {
        self.inner.max_receive_segments()
    }

    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }
}
