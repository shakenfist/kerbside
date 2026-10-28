//! Moving a display channel between relaying and transcoding while it runs.
//!
//! An experiment, run with the hidden `--transcode-switch-after-secs N`: the
//! session's first display channel starts in one mode (transcoded with
//! `--transcode-display`, relayed without), and each time it has spent N
//! seconds in a mode it switches to the other. It exists to measure what a
//! switch costs, not as a way to choose a mode.
//!
//! The client leg stays open throughout. A switch stops the current mode
//! between two messages to the client, closes the backend display channel,
//! and dials it again for the other mode. Both modes dial the backend with
//! the transcoder's capabilities ([`super::BACKEND_DISPLAY_CAPS`]), so that
//! spice-server never streams video on either, and the relay never uses
//! GLZ: each relay spell asks spice-server for the client's preferred
//! compression with GLZ swapped for LZ ([`without_glz`]), or for `AUTO_LZ`
//! if the client asked for nothing. GLZ cannot survive a switch. Each new
//! backend display channel starts a fresh GLZ dictionary whose image ids
//! start again at 0, while the client's GLZ window still holds the images
//! of the last channel; spice-gtk 0.42 then grows its window on every
//! image until the size overflows, and dies of a division by zero.
//!
//! - **Relay to transcode.** The relay ends when its backend leg reads as
//!   closed ([`BackendLeg`]), which its server-to-client pump sees only
//!   between messages. The transcoder starts with [`Start::AfterRelay`]: no
//!   `DISPLAY_INIT` to wait for, and a first frame that clears the streams,
//!   cached images and palettes spice-server may have left with the client,
//!   then draws the whole picture losslessly over the surface spice-server
//!   gave the client, if it is the same size.
//! - **Transcode to relay.** The transcoder stops between frames
//!   ([`Ended::Stopped`]). The new backend display channel waits for a
//!   `DISPLAY_INIT` that the client sent once, at the start, so the client's
//!   own is replayed to it, with its `PREFERRED_COMPRESSION` if it sent one.
//!   spice-server then sends its usual start sequence, which the relay
//!   forwards: a new primary surface, all of it drawn.
//!
//! spice-server refuses a display channel that arrives while the session's
//! previous one is still being torn down ("duplicate channel"), by closing
//! it after the link. A refused channel is dialled again, after a short
//! pause, up to [`MAX_DIALS`] times; each refusal is logged.
//!
//! [`ClientLeg`] keeps the client's messages whole across a switch: a mode
//! only ever reads complete messages, so a message the client was half way
//! through sending reaches the next mode intact. It also keeps the
//! `DISPLAY_INIT` and `PREFERRED_COMPRESSION` the relay replays, takes GLZ
//! out of the latter, and follows the size of the client's primary surface
//! in what is written to it.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{ready, Context, Poll};
use std::time::Duration;

use anyhow::{bail, Result};
use shakenfist_spice_protocol::constants::image_compression;
use shakenfist_spice_protocol::link::SpiceStream;
use shakenfist_spice_protocol::messages::{MessageHeader, PreferredCompression, WireType};
use shakenfist_spice_protocol::{display_client, display_server, ChannelType};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::time::Instant;
use tokio_util::sync::{CancellationToken, WaitForCancellationFutureOwned};
use tracing::{info, warn};

use super::geometry::Size;
use super::{message, run_channel, set_client_lowat, Ended, Options, PacingMode, Start};
use crate::caps::ClientCaps;
use crate::pb;
use crate::policy::FirewallPolicy;
use crate::relay::MAX_MESSAGE_SIZE;
use crate::session::SharedState;

/// How many times one switch dials the backend before giving up, counting
/// the dials spice-server refuses.
pub const MAX_DIALS: u32 = 10;

/// The pause before dialling a refused display channel again, multiplied by
/// the number of refusals so far.
const REDIAL_PAUSE: Duration = Duration::from_millis(50);

/// How long a re-dialled relay waits for spice-server to answer the replayed
/// `DISPLAY_INIT`. spice-server closes a refused channel at once, and starts
/// sending to an accepted one as soon as it has the `DISPLAY_INIT`.
const ACCEPT_TIMEOUT: Duration = Duration::from_secs(10);

/// `compression` with GLZ swapped for its non-GLZ counterpart: what a relay
/// spell asks spice-server for (see the module documentation).
pub fn without_glz(compression: u8) -> u8 {
    match compression {
        image_compression::AUTO_GLZ => image_compression::AUTO_LZ,
        image_compression::GLZ => image_compression::LZ,
        other => other,
    }
}

/// The two ways a display channel can run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Relay,
    Transcode,
}

impl Mode {
    fn other(self) -> Self {
        match self {
            Self::Relay => Self::Transcode,
            Self::Transcode => Self::Relay,
        }
    }
}

/// How one spell in a mode ended.
enum Spell {
    /// It stopped for a switch, and the client leg is whole.
    Stopped,
    /// The client, the backend or the control plane ended the channel.
    Ended,
    /// spice-server closed the new backend channel before using it.
    Refused,
}

/// Run a display channel that moves between relaying and transcoding every
/// `every`, until the client, the backend or the control plane ends it.
/// `dial` opens the backend display channel, linked with
/// [`super::BACKEND_DISPLAY_CAPS`]; it is called once for each spell, and
/// again for each refusal.
///
/// Returns `Err` only if a dial fails, or spice-server refuses a switch
/// [`MAX_DIALS`] times; the caller closes the client leg either way.
#[allow(clippy::too_many_arguments)]
pub async fn run<D, F>(
    state: &SharedState,
    policy: Arc<FirewallPolicy>,
    client: SpiceStream,
    client_caps: &ClientCaps,
    connection_ref: &str,
    target: &pb::Target,
    cancel: CancellationToken,
    options: &Options,
    every: Duration,
    dial: D,
) -> Result<()>
where
    D: FnMut() -> F,
    F: Future<Output = Result<SpiceStream>>,
{
    let mut client = ClientLeg::new(client);
    let switching = Switching {
        state,
        policy,
        client_caps,
        connection_ref,
        target,
        cancel,
        options,
        every,
    };
    switching.run(&mut client, dial).await
}

/// One switching display channel's fixed parts.
struct Switching<'a> {
    state: &'a SharedState,
    policy: Arc<FirewallPolicy>,
    client_caps: &'a ClientCaps,
    connection_ref: &'a str,
    target: &'a pb::Target,
    cancel: CancellationToken,
    options: &'a Options,
    every: Duration,
}

impl Switching<'_> {
    async fn run<D, F>(&self, client: &mut ClientLeg<SpiceStream>, mut dial: D) -> Result<()>
    where
        D: FnMut() -> F,
        F: Future<Output = Result<SpiceStream>>,
    {
        let connection_ref = self.connection_ref;
        let mut mode = if self.options.start_transcoded {
            Mode::Transcode
        } else {
            Mode::Relay
        };
        info!(
            %connection_ref,
            ?mode,
            every_secs = self.every.as_secs_f64(),
            "this display channel switches between relaying and transcoding \
             (--transcode-switch-after-secs): an experiment"
        );
        // When the last spell stopped for a switch, until the next starts.
        let mut stopped_at: Option<Instant> = None;
        loop {
            let mut refusals = 0;
            let spell = loop {
                let backend = dial().await?;
                if let Some(at) = stopped_at {
                    info!(
                        %connection_ref,
                        ?mode,
                        dial = refusals + 1,
                        since_stop_ms = at.elapsed().as_secs_f64() * 1000.0,
                        "dialled the backend display channel for the switch"
                    );
                }
                let spell = match mode {
                    Mode::Relay => self.relay(client, backend, stopped_at.is_some()).await,
                    Mode::Transcode => self.transcode(client, backend, stopped_at.is_some()).await,
                };
                if !matches!(spell, Spell::Refused) {
                    break spell;
                }
                refusals += 1;
                warn!(
                    %connection_ref,
                    ?mode,
                    refusals,
                    "spice-server refused the new display channel (the previous one was \
                     still closing); dialling again"
                );
                if refusals >= MAX_DIALS {
                    bail!("spice-server refused the display channel {refusals} times");
                }
                tokio::time::sleep(REDIAL_PAUSE * refusals).await;
            };
            match spell {
                Spell::Stopped => {
                    stopped_at = Some(Instant::now());
                    mode = mode.other();
                }
                Spell::Ended | Spell::Refused => return Ok(()),
            }
        }
    }

    /// Wait `every`, then ask `phase` to stop, and wait for it to end.
    async fn spell<P: Future>(&self, phase: P, stop: &CancellationToken, mode: Mode) -> P::Output {
        tokio::pin!(phase);
        tokio::select! {
            output = &mut phase => output,
            () = tokio::time::sleep(self.every) => {
                info!(
                    connection_ref = %self.connection_ref,
                    from = ?mode,
                    to = ?mode.other(),
                    "switching the display channel"
                );
                stop.cancel();
                phase.await
            }
        }
    }

    /// One spell relaying. `resumed` says whether a transcoder had the client
    /// before it, in which case the backend is given the client's
    /// `DISPLAY_INIT` and must accept it.
    async fn relay(
        &self,
        client: &mut ClientLeg<SpiceStream>,
        mut backend: SpiceStream,
        resumed: bool,
    ) -> Spell {
        let connection_ref = self.connection_ref;
        // What compression to ask spice-server for: never GLZ.
        let preference = client.preferred_compression.clone().unwrap_or_else(|| {
            message(
                display_client::PREFERRED_COMPRESSION,
                &PreferredCompression {
                    image_compression: image_compression::AUTO_LZ,
                },
            )
        });
        let mut prefix = Vec::new();
        if !resumed {
            // The client's own DISPLAY_INIT follows through the relay.
            if let Err(e) = backend.write_all(&preference).await {
                warn!(
                    %connection_ref,
                    error = %e,
                    "the backend display channel failed before the relay started"
                );
                return Spell::Ended;
            }
        } else {
            // The transcoder may have tightened the socket's unsent-data
            // limit; the relay runs with the kernel's.
            set_client_lowat(client.get_ref(), 0, connection_ref);
            match replay_init(client, &preference, &mut backend).await {
                Ok(Some(first)) => prefix = first,
                Ok(None) => return Spell::Refused,
                Err(e) => {
                    warn!(
                        %connection_ref,
                        error = format!("{e:#}"),
                        "the new backend display channel failed before the relay started"
                    );
                    return Spell::Refused;
                }
            }
            info!(
                %connection_ref,
                first_bytes = prefix.len(),
                "the backend accepted the new display channel; relaying"
            );
        }
        let stop = CancellationToken::new();
        let backend = BackendLeg::new(backend, prefix, &stop);
        let relay = crate::relay::run(
            self.state,
            Arc::clone(&self.policy),
            &mut *client,
            backend,
            ChannelType::Display,
            connection_ref,
            self.target,
            self.cancel.clone(),
        );
        // The relay always returns Ok; how it ended is read from the legs.
        let _ = self.spell(relay, &stop, Mode::Relay).await;
        if self.cancel.is_cancelled() || client.closed || !stop.is_cancelled() {
            Spell::Ended
        } else {
            Spell::Stopped
        }
    }

    /// One spell transcoding. `resumed` says whether a relay had the client
    /// before it.
    async fn transcode(
        &self,
        client: &mut ClientLeg<SpiceStream>,
        backend: SpiceStream,
        resumed: bool,
    ) -> Spell {
        if self.options.pacing == PacingMode::Socket {
            set_client_lowat(
                client.get_ref(),
                self.options.notsent_lowat,
                self.connection_ref,
            );
        }
        let start = if resumed {
            Start::AfterRelay {
                preferred_compression: client.preferred_compression(),
                client_surface: client.written.primary,
            }
        } else {
            Start::Fresh
        };
        let stop = CancellationToken::new();
        let transcoder = run_channel(
            self.state,
            Arc::clone(&self.policy),
            &mut *client,
            backend,
            self.client_caps,
            self.connection_ref,
            self.target,
            self.cancel.clone(),
            self.options,
            start,
            Some(stop.clone()),
        );
        match self.spell(transcoder, &stop, Mode::Transcode).await {
            Ended::Stopped if !client.closed => Spell::Stopped,
            Ended::Refused => Spell::Refused,
            Ended::Stopped | Ended::Closed => Spell::Ended,
        }
    }
}

/// Give a re-dialled backend the client's `DISPLAY_INIT` and `preference`,
/// a `PREFERRED_COMPRESSION`, and wait for the first bytes spice-server
/// sends back. Returns them, or `None` if spice-server closed the channel
/// instead, as it does to one it refuses.
async fn replay_init<S, B>(
    client: &ClientLeg<S>,
    preference: &[u8],
    backend: &mut B,
) -> Result<Option<Vec<u8>>>
where
    B: AsyncRead + AsyncWrite + Unpin,
{
    let Some(init) = &client.init else {
        bail!("the client never sent DISPLAY_INIT, so there is none to replay");
    };
    let mut replay = init.clone();
    replay.extend_from_slice(preference);
    if backend.write_all(&replay).await.is_err() || backend.flush().await.is_err() {
        return Ok(None);
    }
    let mut first = vec![0; 64 * 1024];
    match tokio::time::timeout(ACCEPT_TIMEOUT, backend.read(&mut first)).await {
        Ok(Ok(0) | Err(_)) => Ok(None),
        Ok(Ok(n)) => {
            first.truncate(n);
            Ok(Some(first))
        }
        Err(_) => bail!(
            "spice-server sent nothing within {}s of the replayed DISPLAY_INIT",
            ACCEPT_TIMEOUT.as_secs()
        ),
    }
}

/// The client leg of a switching display channel. Reads hand on only whole
/// SPICE messages, holding back the start of one still arriving, so that a
/// mode which stops between reads leaves no message half taken. Writes go
/// straight to the client.
///
/// A message too large to frame (over the relay's own cap) turns the
/// holding back off for the rest of the channel, so that whichever mode is
/// reading sees the header and refuses it, as it would without this layer.
///
/// A `PREFERRED_COMPRESSION` is handed on with GLZ swapped for LZ
/// ([`without_glz`]), so that a relay never uses GLZ.
///
/// What is written to the client is framed too ([`Written`]), to know the
/// size of the primary surface the client holds.
pub struct ClientLeg<S> {
    inner: S,
    /// Bytes read from the client and not yet handed on: `whole` bytes of
    /// complete messages, then the start of the next.
    pending: Vec<u8>,
    whole: usize,
    framing: bool,
    /// The client's `DISPLAY_INIT` and latest `PREFERRED_COMPRESSION` (with
    /// GLZ taken out), each a whole message with its header.
    init: Option<Vec<u8>>,
    preferred_compression: Option<Vec<u8>>,
    /// Whether the client has closed its side.
    closed: bool,
    written: Written,
}

/// Follows the display messages written to the client, by whoever wrote
/// them, for the size of the primary surface it was last given.
#[derive(Debug, Default)]
struct Written {
    header: Vec<u8>,
    msg_type: u16,
    /// Body bytes still to come of the message being written.
    remaining: usize,
    /// The start of its body: as much as a surface message needs.
    body: Vec<u8>,
    primary: Option<Size>,
}

impl Written {
    /// `SURFACE_CREATE` opens with the surface id, width and height.
    const BODY_NEEDED: usize = 12;

    fn track(&mut self, mut bytes: &[u8]) {
        while !bytes.is_empty() {
            if self.header.len() < MessageHeader::SIZE {
                let take = (MessageHeader::SIZE - self.header.len()).min(bytes.len());
                self.header.extend_from_slice(&bytes[..take]);
                bytes = &bytes[take..];
                if self.header.len() == MessageHeader::SIZE {
                    let Ok(header) = MessageHeader::read(&self.header) else {
                        return;
                    };
                    self.msg_type = header.message_type;
                    self.remaining = header.message_size as usize;
                    self.body.clear();
                    if self.remaining == 0 {
                        self.finish();
                    }
                }
                continue;
            }
            let take = self.remaining.min(bytes.len());
            let keep = Self::BODY_NEEDED.saturating_sub(self.body.len()).min(take);
            self.body.extend_from_slice(&bytes[..keep]);
            self.remaining -= take;
            bytes = &bytes[take..];
            if self.remaining == 0 {
                self.finish();
            }
        }
    }

    fn finish(&mut self) {
        let word = |at: usize| {
            self.body
                .get(at..at + 4)
                .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
        };
        match (self.msg_type, word(0)) {
            (display_server::SURFACE_CREATE, Some(0)) => {
                if let (Some(width), Some(height)) = (word(4), word(8)) {
                    self.primary = Some(Size { width, height });
                }
            }
            (display_server::SURFACE_DESTROY, Some(0)) => self.primary = None,
            _ => {}
        }
        self.header.clear();
    }
}

impl<S> ClientLeg<S> {
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            pending: Vec::new(),
            whole: 0,
            framing: true,
            init: None,
            preferred_compression: None,
            closed: false,
            written: Written::default(),
        }
    }

    pub fn get_ref(&self) -> &S {
        &self.inner
    }

    /// Whether the client has closed its side.
    #[cfg(test)]
    pub fn closed_for_test(&self) -> bool {
        self.closed
    }

    /// The image compression the client last asked for, with GLZ taken out,
    /// if it asked.
    pub fn preferred_compression(&self) -> Option<u8> {
        let message = self.preferred_compression.as_ref()?;
        PreferredCompression::decode(message.get(MessageHeader::SIZE..)?)
            .ok()
            .map(|p| p.image_compression)
    }

    /// Move the boundary of what may be handed on past every complete
    /// message in `pending`, keeping the two the relay may replay.
    fn frame(&mut self) {
        while self.framing && self.pending.len() - self.whole >= MessageHeader::SIZE {
            let at = self.whole;
            let Ok(header) = MessageHeader::read(&self.pending[at..at + MessageHeader::SIZE])
            else {
                self.framing = false;
                break;
            };
            if header.message_size > MAX_MESSAGE_SIZE {
                self.framing = false;
                break;
            }
            let end = at + MessageHeader::SIZE + header.message_size as usize;
            if self.pending.len() < end {
                return;
            }
            match header.message_type {
                display_client::INIT => self.init = Some(self.pending[at..end].to_vec()),
                display_client::PREFERRED_COMPRESSION => {
                    if let Some(compression) = self.pending.get_mut(at + MessageHeader::SIZE) {
                        *compression = without_glz(*compression);
                    }
                    self.preferred_compression = Some(self.pending[at..end].to_vec());
                }
                _ => {}
            }
            self.whole = end;
        }
        if !self.framing {
            self.whole = self.pending.len();
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for ClientLeg<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;
        loop {
            if this.whole > 0 {
                let n = this.whole.min(buf.remaining());
                buf.put_slice(&this.pending[..n]);
                this.pending.drain(..n);
                this.whole -= n;
                return Poll::Ready(Ok(()));
            }
            let mut chunk = [0u8; 16 * 1024];
            let mut read = ReadBuf::new(&mut chunk);
            ready!(Pin::new(&mut this.inner).poll_read(cx, &mut read))?;
            if read.filled().is_empty() {
                // The client closed; the start of a message it never
                // finished is dropped.
                this.closed = true;
                return Poll::Ready(Ok(()));
            }
            this.pending.extend_from_slice(read.filled());
            this.frame();
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for ClientLeg<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        let written = ready!(Pin::new(&mut this.inner).poll_write(cx, buf))?;
        this.written.track(&buf[..written]);
        Poll::Ready(Ok(written))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// The backend leg of a relay spell. It reads as closed once `stop` fires,
/// which is how the relay is ended for a switch: its server-to-client pump
/// reads only between messages, and on that end of file flushes what it has
/// forwarded and returns, so the client is never left with part of a
/// message. Bytes read from the backend before the relay began (while
/// checking spice-server accepted the channel) come first.
pub struct BackendLeg<S> {
    inner: S,
    prefix: Vec<u8>,
    stop: Pin<Box<WaitForCancellationFutureOwned>>,
    stopped: bool,
}

impl<S> BackendLeg<S> {
    pub fn new(inner: S, prefix: Vec<u8>, stop: &CancellationToken) -> Self {
        Self {
            inner,
            prefix,
            stop: Box::pin(stop.clone().cancelled_owned()),
            stopped: false,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for BackendLeg<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;
        if !this.stopped && this.stop.as_mut().poll(cx).is_ready() {
            this.stopped = true;
        }
        if this.stopped {
            return Poll::Ready(Ok(()));
        }
        if !this.prefix.is_empty() {
            let n = this.prefix.len().min(buf.remaining());
            buf.put_slice(&this.prefix[..n]);
            this.prefix.drain(..n);
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for BackendLeg<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shakenfist_spice_protocol::messages::make_message;

    /// Read what `leg` hands on in one read.
    async fn read_once<S: AsyncRead + Unpin>(leg: &mut ClientLeg<S>) -> Vec<u8> {
        let mut buf = vec![0; 64 * 1024];
        let n = leg.read(&mut buf).await.unwrap();
        buf.truncate(n);
        buf
    }

    #[tokio::test]
    async fn the_client_leg_hands_on_only_whole_messages() {
        let init = make_message(display_client::INIT, &[1; 14]);
        let first = make_message(
            display_client::PREFERRED_COMPRESSION,
            &[image_compression::AUTO_GLZ],
        );
        let second = make_message(
            display_client::PREFERRED_COMPRESSION,
            &[image_compression::LZ4],
        );
        let ack = make_message(display_client::ACK, &[]);
        let (mut near, far) = tokio::io::duplex(64 * 1024);
        let mut leg = ClientLeg::new(far);

        // INIT and the start of a PREFERRED_COMPRESSION: only INIT is handed on.
        near.write_all(&init).await.unwrap();
        near.write_all(&first[..4]).await.unwrap();
        assert_eq!(read_once(&mut leg).await, init);
        assert_eq!(leg.init.as_deref(), Some(init.as_slice()));
        assert_eq!(leg.preferred_compression(), None);

        // The rest of it, another, and an ACK: all three at once, with GLZ
        // taken out of the first.
        near.write_all(&first[4..]).await.unwrap();
        near.write_all(&second).await.unwrap();
        near.write_all(&ack).await.unwrap();
        let mut want = make_message(
            display_client::PREFERRED_COMPRESSION,
            &[image_compression::AUTO_LZ],
        );
        want.extend_from_slice(&second);
        want.extend_from_slice(&ack);
        assert_eq!(read_once(&mut leg).await, want);
        assert_eq!(
            leg.preferred_compression(),
            Some(image_compression::LZ4),
            "the latest preference is kept"
        );

        // A message the client never finishes is never handed on.
        near.write_all(&ack[..3]).await.unwrap();
        drop(near);
        assert!(read_once(&mut leg).await.is_empty());
        assert!(leg.closed);
    }

    #[test]
    fn the_client_leg_follows_the_primary_surface_written() {
        let create = |id: u32, width: u32, height: u32| {
            let mut body = Vec::new();
            for word in [id, width, height, 32, 1] {
                body.extend_from_slice(&word.to_le_bytes());
            }
            make_message(display_server::SURFACE_CREATE, &body)
        };
        let mut written = Written::default();
        // Split at awkward places, with other messages around.
        let mut wire = make_message(display_server::MARK, &[]);
        wire.extend(create(0, 1280, 800));
        wire.extend(create(3, 64, 64));
        wire.extend(make_message(display_server::DRAW_COPY, &[7; 40]));
        for chunk in wire.chunks(5) {
            written.track(chunk);
        }
        assert_eq!(
            written.primary,
            Some(Size {
                width: 1280,
                height: 800
            }),
            "an off-screen surface is not the primary"
        );
        written.track(&make_message(display_server::SURFACE_DESTROY, &[0; 4]));
        assert_eq!(written.primary, None);
    }

    #[test]
    fn glz_is_swapped_for_lz() {
        assert_eq!(
            without_glz(image_compression::AUTO_GLZ),
            image_compression::AUTO_LZ
        );
        assert_eq!(without_glz(image_compression::GLZ), image_compression::LZ);
        for kept in [
            image_compression::OFF,
            image_compression::AUTO_LZ,
            image_compression::QUIC,
            image_compression::LZ,
            image_compression::LZ4,
        ] {
            assert_eq!(without_glz(kept), kept);
        }
    }

    #[tokio::test]
    async fn the_client_leg_passes_a_message_too_large_to_frame() {
        // A header claiming more than the relay's cap is handed on as it
        // arrives, so that the mode reading it refuses it.
        let mut huge = Vec::new();
        MessageHeader {
            message_type: display_client::INIT,
            message_size: MAX_MESSAGE_SIZE + 1,
        }
        .write(&mut huge)
        .unwrap();
        huge.extend_from_slice(&[0; 10]);
        let (mut near, far) = tokio::io::duplex(64 * 1024);
        let mut leg = ClientLeg::new(far);
        near.write_all(&huge).await.unwrap();
        assert_eq!(read_once(&mut leg).await, huge);
        assert!(leg.init.is_none());
    }

    #[tokio::test]
    async fn the_backend_leg_reads_as_closed_once_stopped() {
        let (mut near, far) = tokio::io::duplex(64 * 1024);
        let stop = CancellationToken::new();
        let mut leg = BackendLeg::new(far, b"first".to_vec(), &stop);
        let mut buf = [0; 64];

        // The bytes read before the relay began come first, then the rest.
        let n = leg.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"first");
        near.write_all(b"then").await.unwrap();
        let n = leg.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"then");

        // A read waiting on a silent backend ends when the stop fires.
        let reader = tokio::spawn(async move {
            let mut buf = [0; 64];
            let n = leg.read(&mut buf).await.unwrap();
            (n, leg)
        });
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(!reader.is_finished(), "nothing to read yet");
        stop.cancel();
        let (n, mut leg) = tokio::time::timeout(Duration::from_secs(5), reader)
            .await
            .expect("the stop ends the read")
            .unwrap();
        assert_eq!(n, 0, "a stopped backend reads as closed");

        // And so does every read after it, whatever the backend sends.
        near.write_all(b"late").await.unwrap();
        assert_eq!(leg.read(&mut buf).await.unwrap(), 0);
    }
}
