//! The transcoding display channel: terminate the display channel, decode
//! it, and re-encode it for the client.
//!
//! Built only with the `transcode` cargo feature, and used only with
//! `--transcode-display`. It replaces the relay for a session's first
//! display channel; every other channel is relayed as before. See
//! `docs/proxy-architecture.md` for what it is for and how to run it.
//!
//! # The two legs
//!
//! - **Backend.** The hypervisor is dialled with [`BACKEND_DISPLAY_CAPS`]
//!   rather than the client's capabilities, because what reads the backend
//!   is ryll's renderer ([`decode`]), not the client. The renderer applies
//!   nothing itself: its decoded events come back here and are applied to a
//!   `SurfaceMirror`, whose primary surface records where each draw landed.
//! - **Client.** Kerbside answers as a display server, in the minimum
//!   sequence spice-gtk accepts: it waits for the client's `DISPLAY_INIT`,
//!   then sends `SURFACE_CREATE` for the primary surface, a full lossless
//!   draw, `MONITORS_CONFIG` if the client has that capability, and `MARK`.
//!   After that each frame is the draws that bring the client up to date,
//!   then `MARK`. A new primary surface from the backend (a resize, or a
//!   destroy and create) is sent as `SURFACE_DESTROY`, then the same start
//!   sequence. Nothing is ever sent as a video stream, and no image asks
//!   the client to cache it. The client's reader has no idle timeout,
//!   because a client paced on the socket has nothing to say once
//!   initialised; TCP keepalive ends a client that has gone, and a write to
//!   the client that makes no progress for
//!   [`STALLED_WRITE_TIMEOUT`](crate::relay::STALLED_WRITE_TIMEOUT) ends one
//!   that is alive but has stopped reading.
//!
//! # From damage to draws
//!
//! [`capture`] reads the mirror's damaged rectangles as a capture, and
//! [`updates`], the update pipeline copied from andris, compares it with a
//! shadow of what the client holds, a 64-pixel tile at a time, and encodes
//! what changed: JPEG for rectangles its classifier calls photographic, LZ4
//! or a raw bitmap otherwise, at most 32 rectangles a frame and at most
//! 4 MiB raw a draw. An area sent as JPEG is sent again losslessly once it
//! has gone `--transcode-lossless-delay-ms` without damage.
//!
//! # Pacing
//!
//! [`pacing`] says when a frame may start. One frame is written at a time;
//! while the client is behind, damage merges in the mirror, so the next
//! frame reads the pixels as they are by then and nothing superseded is
//! sent. By default the client socket's `TCP_NOTSENT_LOWAT` sets the pace;
//! a hidden measurement flag paces on a SPICE ACK window instead.
//!
//! # What it does not do
//!
//! Only the first display channel (channel id 0) is transcoded; a second is
//! relayed, with a log line. The choice is made at connect and cannot change
//! later: what the renderer cannot draw (see [`decode`]) is logged and
//! counted, and the client shows a stale region there. The scope is a
//! virtio-gpu or std-vga guest, whose display reaches spice-server as bitmap
//! draws on the primary surface.
//!
//! # The copy of andris's pipeline
//!
//! [`geometry`] and [`updates`] are copied from andris at commit
//! e29929fa88bbafebdd1046138112c1a4cfecd2cf; each file's header says what
//! was changed. They are a copy rather than a dependency because andris is
//! one crate that depends on X11, audio and its own platform types. If the
//! transcoder is kept, the pipeline belongs in a crate both share, and this
//! copy is what gets deleted.

mod capture;
mod decode;
pub(crate) mod geometry;
mod pacing;
pub(crate) mod updates;

use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use shakenfist_spice_protocol::constants::{capabilities, image_compression, surface_fmt};
use shakenfist_spice_protocol::link::SpiceStream;
use shakenfist_spice_protocol::messages::{
    make_message, DisplayHead, DisplayInit, DisplayMonitorsConfig, MessageHeader,
    PreferredCompression, SetAck, SurfaceCreate, SurfaceDestroy, WireType,
};
use shakenfist_spice_protocol::{display_client, display_server, ChannelType};
use shakenfist_spice_renderer::{ChannelEvent, DrawOutcome, SurfaceMirror};
use socket2::SockRef;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::caps::ClientCaps;
use crate::pb;
use crate::policy::{Direction, EnforcingPolicy, FirewallPolicy, Policy, Verdict, VerdictTally};
use crate::relay::STALLED_WRITE_TIMEOUT;
use crate::session::SharedState;
pub use pacing::PacingMode;
use pacing::{Pacer, ACK_GENERATION};
use updates::{EncodeOptions, JpegQuality, LossyTiles, Update, UpdateEncoder, SURFACE_ID};

/// The display channel capabilities the backend leg advertises when it
/// transcodes, whatever the client advertised. They describe ryll's
/// renderer, which is what reads the backend:
///
/// - `LZ4_COMPRESSION` and `PREF_COMPRESSION`, so that the renderer's
///   `PREFERRED_COMPRESSION` of LZ4 is honoured. Without LZ4, spice-server
///   compresses draws with QUIC, and turns QUIC into lossy JPEG whenever
///   `jpeg-wan-compression` is on (`server/dcc.cpp:660-667`), which qemu's
///   default `auto` does when its bandwidth test finds a slow link.
/// - `MULTI_CODEC` with no `CODEC_*` bit, so that spice-server creates no
///   video encoder and sends frames as ordinary draws:
///   `dcc_create_video_encoder` skips every codec whose capability a
///   `MULTI_CODEC` client lacks (`server/video-stream.cpp:801-835`), and
///   without `MULTI_CODEC` it would fall back to MJPEG.
/// - `PREF_VIDEO_CODEC_TYPE`, since the renderer always sends that message;
///   with no codec capability it changes nothing.
/// - `MONITORS_CONFIG`, which the renderer reads.
///
/// Left out: `STREAM_REPORT` and `SIZED_STREAM` (no streams),
/// `COMPOSITE` and `A8_SURFACE` (draws and surfaces the renderer cannot
/// draw), and `GL_SCANOUT` (a local-socket display the proxy cannot reach).
pub const BACKEND_DISPLAY_CAPS: [u32; 1] = [capabilities::DISPLAY_LZ4_COMPRESSION
    | capabilities::DISPLAY_PREF_COMPRESSION
    | capabilities::DISPLAY_MULTI_CODEC
    | capabilities::DISPLAY_PREF_VIDEO_CODEC_TYPE
    | capabilities::DISPLAY_MONITORS_CONFIG];

/// `SPICE_SURFACE_FLAGS_PRIMARY` (spice-protocol `enums.h`): the surface is
/// the display itself.
const SURFACE_FLAGS_PRIMARY: u32 = 1 << 0;

/// The mirror key of the backend's primary surface.
const PRIMARY: (u8, u32) = (decode::RENDERER_CHANNEL_ID, 0);

/// The largest message the client may send. Display channel client
/// messages are a few bytes; the relay's own backstop applies on top of the
/// firewall policy's caps.
const MAX_CLIENT_MESSAGE: u32 = crate::relay::MAX_MESSAGE_SIZE;

/// The transcoder's command line flags. Process-wide: every session's first
/// display channel is transcoded when `--transcode-display` is set.
#[derive(Debug, Clone, clap::Args)]
pub struct TranscodeArgs {
    /// Transcode each session's display channel instead of relaying it: decode
    /// the backend's display with ryll's renderer and send the client JPEG and
    /// lossless draws of what changed, paced by the client socket. An
    /// experiment; off by default. See docs/proxy-architecture.md.
    #[arg(long)]
    pub transcode_display: bool,

    /// The JPEG quality, 1 to 100, for areas the transcoder judges
    /// photographic; 0 sends everything losslessly.
    #[arg(long, default_value_t = 85, value_parser = clap::value_parser!(u8).range(0..=100))]
    pub transcode_jpeg_quality: u8,

    /// How long, in milliseconds, an area sent as JPEG must go without change
    /// before it is sent again losslessly.
    #[arg(long, default_value_t = 500)]
    pub transcode_lossless_delay_ms: u64,

    /// `TCP_NOTSENT_LOWAT` for a transcoded display channel's client socket, in
    /// bytes: the most unsent data the kernel queues before the transcoder's
    /// writes wait, and so how far ahead of the link it may run.
    #[arg(long, default_value_t = 65536, value_parser = clap::value_parser!(u32).range(1..))]
    pub transcode_notsent_lowat_bytes: u32,

    /// A measurement option: pace the transcoder on a SPICE ACK window of this
    /// many messages, as spice-server does, instead of on the client socket. 0
    /// (the default) paces on the socket.
    #[arg(long, default_value_t = 0, hide = true)]
    pub transcode_ack_window: u32,
}

/// How a transcoding display channel runs, from [`TranscodeArgs`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Options {
    /// The quality to send photographic areas at, or `None` for lossless
    /// only.
    pub jpeg_quality: Option<JpegQuality>,
    /// How long a lossy area must be still before its lossless refresh.
    pub lossless_delay: Duration,
    /// The client socket's `TCP_NOTSENT_LOWAT`, under socket pacing.
    pub notsent_lowat: u32,
    pub pacing: PacingMode,
}

impl Options {
    /// The options `args` ask for, or `None` without `--transcode-display`.
    pub fn from_args(args: &TranscodeArgs) -> Option<Self> {
        if !args.transcode_display {
            return None;
        }
        Some(Self {
            jpeg_quality: JpegQuality::new(args.transcode_jpeg_quality),
            lossless_delay: Duration::from_millis(args.transcode_lossless_delay_ms),
            notsent_lowat: args.transcode_notsent_lowat_bytes,
            pacing: match args.transcode_ack_window {
                0 => PacingMode::Socket,
                window => PacingMode::AckWindow(window),
            },
        })
    }
}

/// The options to transcode this channel with, or `None` to relay it: only
/// a display channel, only channel id 0, and only when transcoding is on.
pub fn choose(
    state: &SharedState,
    channel_type: ChannelType,
    channel_id: u8,
    connection_ref: &str,
) -> Option<Arc<Options>> {
    let options = state.transcode.as_ref()?;
    if channel_type != ChannelType::Display {
        return None;
    }
    if channel_id != 0 {
        info!(
            %connection_ref,
            channel_id,
            "only the first display channel is transcoded; relaying this one"
        );
        return None;
    }
    Some(Arc::clone(options))
}

/// One message from the client, after the firewall forwarded it.
#[derive(Debug)]
struct ClientMessage {
    msg_type: u16,
    payload: Vec<u8>,
}

/// Run a transcoding display channel between `client`, a linked and
/// authorized client display channel, and `backend`, the hypervisor's
/// display channel linked with [`BACKEND_DISPLAY_CAPS`], until either ends
/// or the session is cancelled.
///
/// Like the relay, it firewalls the client's messages with `policy`,
/// counts the bytes on the client leg in `kerbside_proxy_bytes_relayed_total`,
/// records one coalesced firewall-verdict audit event at the end, and
/// returns `Ok(())` however it ended: the caller closes both legs either way.
#[allow(clippy::too_many_arguments)]
pub async fn run(
    state: &SharedState,
    policy: Arc<FirewallPolicy>,
    client: SpiceStream,
    backend: SpiceStream,
    client_caps: &ClientCaps,
    connection_ref: &str,
    target: &pb::Target,
    cancel: CancellationToken,
    options: &Options,
) -> Result<()> {
    info!(
        %connection_ref,
        pacing = ?options.pacing,
        jpeg_quality = options.jpeg_quality.map(JpegQuality::get),
        lossless_delay_ms = options.lossless_delay.as_millis() as u64,
        "transcoding display channel starting"
    );
    if options.pacing == PacingMode::Socket {
        set_client_lowat(&client, options.notsent_lowat, connection_ref);
    }

    let tally = Arc::new(VerdictTally::new());
    let pacer = Arc::new(Pacer::new(options.pacing));
    let mut backend = decode::start(backend, Arc::new(decode::Tap::new(connection_ref)));
    let (client_reader, client_writer) = tokio::io::split(client);
    let (message_tx, message_rx) = mpsc::channel(64);
    // One frame in flight at a time: the display only sends the next after
    // the writer says it has finished the last.
    let (frame_tx, frame_rx) = mpsc::channel(1);
    let (done_tx, done_rx) = mpsc::channel(1);

    let reader = read_client(
        client_reader,
        EnforcingPolicy::new(policy, Direction::ClientToServer, Arc::clone(&tally)),
        message_tx,
        connection_ref,
    );
    let writer = write_client(
        client_writer,
        frame_rx,
        done_tx,
        Arc::clone(&pacer),
        connection_ref,
    );
    let mut display = Display::new(options, client_caps, pacer, frame_tx, connection_ref);
    let core = display.run(&mut backend.events, message_rx, done_rx);

    let result = tokio::select! {
        r = reader => r.context("reading the client"),
        r = writer => r.context("writing to the client"),
        r = core => r,
        r = &mut backend.task => match r {
            Ok(Ok(())) => {
                info!(%connection_ref, "the backend display channel closed");
                Ok(())
            }
            Ok(Err(e)) => Err(e.context("decoding the backend display channel")),
            Err(e) => Err(anyhow!("the backend display task failed: {e}")),
        },
        () = cancel.cancelled() => {
            // CI-ORACLE: the same text as the relay's, which
            // tools/direct-qemu/verify-terminate-live.sh and
            // tools/ovirt-e2e/drive-console.py look for.
            info!(
                %connection_ref,
                channel_type = ChannelType::Display.name(),
                "session terminated by control plane; ending relay"
            );
            Ok(())
        }
    };
    // Close the backend leg with the client leg.
    backend.task.abort();

    match &result {
        Ok(()) => info!(%connection_ref, "transcoding display channel ended"),
        Err(e) => warn!(
            %connection_ref,
            error = format!("{e:#}"),
            "transcoding display channel ended with error"
        ),
    }
    crate::relay::record_verdict_summary(
        state,
        &tally,
        ChannelType::Display,
        connection_ref,
        target,
    )
    .await;
    Ok(())
}

/// Set `TCP_NOTSENT_LOWAT` on the client socket, so that the kernel takes
/// no more from the writer while `bytes` are still unsent. Best-effort: a
/// failure leaves the socket's buffer as the pace, and is logged.
fn set_client_lowat(client: &SpiceStream, bytes: u32, connection_ref: &str) {
    if let Err(e) = SockRef::from(crate::backend::tcp_of(client)).set_tcp_notsent_lowat(bytes) {
        warn!(
            %connection_ref,
            bytes,
            error = %e,
            "setting TCP_NOTSENT_LOWAT on the transcoded client socket failed; continuing"
        );
    }
}

/// Read the client's messages, firewall each with `policy`, and pass those
/// it forwards to the display. Ends with `Ok(())` when the client closes the
/// channel, the display stops listening, or the policy terminates it.
///
/// Unlike the relay, there is no idle timeout: once it has sent
/// `DISPLAY_INIT`, a client paced on the socket has nothing more to say (no
/// `SET_ACK` means no `ACK`s, and the transcoder sends no `PING`). TCP
/// keepalive on the client socket still finds a peer that has gone, and
/// [`write_client`] ends a live one that stops reading.
async fn read_client<R, P>(
    mut reader: R,
    mut policy: P,
    messages: mpsc::Sender<ClientMessage>,
    connection_ref: &str,
) -> Result<()>
where
    R: AsyncRead + Unpin,
    P: Policy,
{
    let channel = ChannelType::Display;
    let dir = Direction::ClientToServer;
    let mut buf: Vec<u8> = Vec::new();
    let mut chunk = vec![0u8; 16 * 1024];
    let mut header_checked = false;
    loop {
        let n = reader.read(&mut chunk).await?;
        if n == 0 {
            debug!(%connection_ref, "the client closed the display channel");
            return Ok(());
        }
        buf.extend_from_slice(&chunk[..n]);
        let mut consumed = 0;
        while buf.len() - consumed >= MessageHeader::SIZE {
            let header = MessageHeader::read(&buf[consumed..consumed + MessageHeader::SIZE])?;
            if header.message_size > MAX_CLIENT_MESSAGE {
                bail!(
                    "client display message size {} exceeds cap {MAX_CLIENT_MESSAGE}",
                    header.message_size
                );
            }
            if !header_checked {
                header_checked = true;
                if policy.check_header(dir, channel, &header) == Verdict::Terminate {
                    warn!(
                        %connection_ref,
                        message_type = header.message_type,
                        message_size = header.message_size,
                        "policy header check verdict Terminate; ending transcoding"
                    );
                    return Ok(());
                }
            }
            let frame_len = MessageHeader::SIZE + header.message_size as usize;
            if buf.len() - consumed < frame_len {
                break;
            }
            let payload = &buf[consumed + MessageHeader::SIZE..consumed + frame_len];
            match policy.inspect(dir, channel, &header, payload) {
                Verdict::Forward => {
                    crate::metrics::add_relayed_bytes(dir, frame_len as u64);
                    let message = ClientMessage {
                        msg_type: header.message_type,
                        payload: payload.to_vec(),
                    };
                    if messages.send(message).await.is_err() {
                        return Ok(());
                    }
                }
                Verdict::Drop => debug!(
                    %connection_ref,
                    message_type = header.message_type,
                    "policy verdict Drop; message swallowed"
                ),
                Verdict::Terminate => {
                    warn!(
                        %connection_ref,
                        message_type = header.message_type,
                        "policy verdict Terminate; ending transcoding"
                    );
                    return Ok(());
                }
            }
            consumed += frame_len;
            header_checked = false;
        }
        buf.drain(..consumed);
    }
}

/// Write each frame the display hands over to the client, then tell the
/// display it is done. Each message waits for room under ACK pacing. Ends
/// with `Ok(())` when the display stops sending frames, or when the client
/// stops taking them.
///
/// The client stops taking frames when a write, a flush or the wait for room
/// under ACK pacing makes no progress for [`STALLED_WRITE_TIMEOUT`]. That is
/// a client whose TCP stack is alive, so keepalive does not end it, but
/// which no longer reads: it advertises a zero window, or never ACKs. The
/// reader has no idle timeout to catch it, so without this bound it would
/// hold the channel, its renderer and its concurrency permit forever. A slow
/// link is not a stall: the bound is on progress, not on how long a frame
/// takes, and it is as generous as the relay's idle-read timeout.
async fn write_client<W>(
    mut writer: W,
    mut frames: mpsc::Receiver<Vec<Vec<u8>>>,
    done: mpsc::Sender<()>,
    pacer: Arc<Pacer>,
    connection_ref: &str,
) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    let stalled = |what: &str| -> Result<()> {
        info!(
            %connection_ref,
            timeout_secs = STALLED_WRITE_TIMEOUT.as_secs(),
            waiting_for = what,
            "the client has stopped taking the display; ending transcoding"
        );
        Ok(())
    };
    while let Some(frame) = frames.recv().await {
        for message in &frame {
            if tokio::time::timeout(STALLED_WRITE_TIMEOUT, pacer.wait_for_room())
                .await
                .is_err()
            {
                return stalled("an ACK");
            }
            if !write_all_progressing(&mut writer, message).await? {
                return stalled("a write");
            }
            pacer.sent();
            crate::metrics::add_relayed_bytes(Direction::ServerToClient, message.len() as u64);
        }
        match tokio::time::timeout(STALLED_WRITE_TIMEOUT, writer.flush()).await {
            Ok(flushed) => flushed?,
            Err(_) => return stalled("a flush"),
        }
        if done.send(()).await.is_err() {
            break;
        }
    }
    Ok(())
}

/// Write all of `buf` to `writer`, as `write_all` does, but give up if one
/// write makes no progress for [`STALLED_WRITE_TIMEOUT`]. Returns whether it
/// wrote everything.
async fn write_all_progressing<W>(writer: &mut W, mut buf: &[u8]) -> std::io::Result<bool>
where
    W: AsyncWrite + Unpin,
{
    while !buf.is_empty() {
        match tokio::time::timeout(STALLED_WRITE_TIMEOUT, writer.write(buf)).await {
            Ok(Ok(0)) => return Err(std::io::ErrorKind::WriteZero.into()),
            Ok(Ok(n)) => buf = &buf[n..],
            Ok(Err(e)) => return Err(e),
            Err(_) => return Ok(false),
        }
    }
    Ok(true)
}

/// A typed message body as a framed message.
fn message<T: WireType>(msg_type: u16, body: &T) -> Vec<u8> {
    let mut payload = Vec::new();
    body.write(&mut payload);
    make_message(msg_type, &payload)
}

/// Whether the first word of `caps` has `bit`.
fn has_cap(caps: &[u32], bit: u32) -> bool {
    caps.first().is_some_and(|word| word & bit != 0)
}

/// The display: the mirror of the backend's surfaces, and what the client
/// was last sent.
struct Display {
    connection_ref: String,
    options: Options,
    pacer: Arc<Pacer>,
    frames: mpsc::Sender<Vec<Vec<u8>>>,
    /// Whether the writer has finished the last frame.
    writer_idle: bool,
    mirror: SurfaceMirror,
    /// The client's surface size, once it has one.
    client_surface: Option<crate::transcode::geometry::Size>,
    /// Whether the backend's primary surface was created or destroyed since
    /// the client's surface was sent.
    restart: bool,
    encoder: UpdateEncoder,
    lossy: LossyTiles,
    /// Whether the client has sent `DISPLAY_INIT`.
    initialised: bool,
    preferred_compression: Option<u8>,
    client_lz4: bool,
    client_monitors_config: bool,
    /// Whether a surface too large to encode has been logged.
    oversize_logged: bool,
}

impl Display {
    fn new(
        options: &Options,
        client_caps: &ClientCaps,
        pacer: Arc<Pacer>,
        frames: mpsc::Sender<Vec<Vec<u8>>>,
        connection_ref: &str,
    ) -> Self {
        Self {
            connection_ref: connection_ref.to_string(),
            options: options.clone(),
            pacer,
            frames,
            writer_idle: true,
            mirror: SurfaceMirror::new(),
            client_surface: None,
            restart: false,
            encoder: UpdateEncoder::new(),
            lossy: LossyTiles::new(options.lossless_delay),
            initialised: false,
            preferred_compression: None,
            client_lz4: has_cap(&client_caps.channel, capabilities::DISPLAY_LZ4_COMPRESSION),
            client_monitors_config: has_cap(
                &client_caps.channel,
                capabilities::DISPLAY_MONITORS_CONFIG,
            ),
            oversize_logged: false,
        }
    }

    /// Apply the backend's events and the client's messages, and send each
    /// frame when the pacing allows, until the backend's events end or the
    /// writer stops.
    async fn run(
        &mut self,
        events: &mut mpsc::Receiver<ChannelEvent>,
        mut messages: mpsc::Receiver<ClientMessage>,
        mut done: mpsc::Receiver<()>,
    ) -> Result<()> {
        if let PacingMode::AckWindow(window) = self.options.pacing {
            let set_ack = SetAck {
                generation: ACK_GENERATION,
                window,
            };
            self.send(vec![message(display_server::SET_ACK, &set_ack)])
                .await?;
        }
        loop {
            if self.initialised && self.pacer.may_start_frame(self.writer_idle) {
                if let Some(frame) = self.next_frame().await? {
                    self.send(frame).await?;
                    continue;
                }
            }
            let now = Instant::now();
            let refresh_at = self.lossy.next_due();
            tokio::select! {
                event = events.recv() => match event {
                    Some(event) => {
                        self.apply(&event);
                        // Apply whatever else has queued before looking at
                        // the damage, so a burst becomes one frame.
                        while let Ok(event) = events.try_recv() {
                            self.apply(&event);
                        }
                    }
                    None => return Ok(()),
                },
                message = messages.recv() => match message {
                    Some(message) => self.handle(&message)?,
                    None => return Ok(()),
                },
                finished = done.recv() => match finished {
                    Some(()) => self.writer_idle = true,
                    None => return Ok(()),
                },
                () = tokio::time::sleep_until(refresh_at.unwrap_or(now)),
                    if refresh_at.is_some_and(|at| at > now) => {}
            }
        }
    }

    /// Hand `frame` to the writer.
    async fn send(&mut self, frame: Vec<Vec<u8>>) -> Result<()> {
        self.writer_idle = false;
        self.frames
            .send(frame)
            .await
            .map_err(|_| anyhow!("the client writer has stopped"))
    }

    /// Apply one of the renderer's events to the mirror.
    fn apply(&mut self, event: &ChannelEvent) {
        match self.mirror.apply_event(event) {
            DrawOutcome::Created { key, .. }
            | DrawOutcome::AutoCreated { key, .. }
            | DrawOutcome::Destroyed { key }
                if key == PRIMARY =>
            {
                self.restart = true;
            }
            _ => {}
        }
    }

    /// Act on one message from the client.
    fn handle(&mut self, message: &ClientMessage) -> Result<()> {
        match message.msg_type {
            display_client::INIT => {
                let init = DisplayInit::decode(&message.payload).context("a malformed INIT")?;
                debug!(
                    connection_ref = %self.connection_ref,
                    cache_size = init.cache_size,
                    glz_dict_window = init.glz_dict_window,
                    "the client's display INIT"
                );
                self.initialised = true;
            }
            display_client::PREFERRED_COMPRESSION => {
                let preferred = PreferredCompression::decode(&message.payload)
                    .context("a malformed PREFERRED_COMPRESSION")?;
                debug!(
                    connection_ref = %self.connection_ref,
                    compression = preferred.image_compression,
                    "the client's preferred compression"
                );
                self.preferred_compression = Some(preferred.image_compression);
            }
            display_client::ACK => self.pacer.acked(),
            other => debug!(
                connection_ref = %self.connection_ref,
                message_type = other,
                "a client display message the transcoder ignores"
            ),
        }
        Ok(())
    }

    /// How images may be encoded, as andris decides it
    /// (`andris/src/server/display.rs`, `encode_options`): LZ4 if the client
    /// can decode it and has not asked for no compression, and JPEG only if
    /// the client leaves the choice to the server and the JPEG quality is
    /// not 0.
    fn encode_options(&self) -> EncodeOptions {
        let preferred = self.preferred_compression;
        let jpeg = match preferred {
            None | Some(image_compression::AUTO_GLZ | image_compression::AUTO_LZ) => {
                self.options.jpeg_quality
            }
            Some(_) => None,
        };
        EncodeOptions {
            lz4: self.client_lz4 && preferred != Some(image_compression::OFF),
            jpeg,
        }
    }

    /// The next frame to send, if there is anything to send: the start
    /// sequence for a new surface, the damage since the last frame, or the
    /// lossless refresh of lossy areas that have gone still.
    async fn next_frame(&mut self) -> Result<Option<Vec<Vec<u8>>>> {
        let now = Instant::now();
        let Some(surface) = self.mirror.surfaces.get_mut(&PRIMARY) else {
            // No surface to refresh from; the client keeps what it shows
            // until the backend creates one.
            if !self.lossy.is_empty() {
                self.lossy.reset(geometry::Size {
                    width: 0,
                    height: 0,
                });
            }
            return Ok(None);
        };
        let size = capture::surface_size(surface);
        if let Err(e) = size.check() {
            if !self.oversize_logged {
                self.oversize_logged = true;
                warn!(
                    connection_ref = %self.connection_ref,
                    error = format!("{e:#}"),
                    "the backend's surface is too large to transcode; sending nothing"
                );
            }
            return Ok(None);
        }

        if self.restart || self.client_surface != Some(size) {
            surface.take_damage();
            let capture = capture::whole(surface)?;
            return self.start_surface(size, capture).await.map(Some);
        }

        if !surface.damage().is_empty() {
            let damage = surface.take_damage();
            self.lossy
                .touch(&capture::damage_region(size, &damage), now);
            let capture = capture::damaged(surface, &damage)?;
            let options = self.encode_options();
            let update = self
                .encode(move |encoder| encoder.update(&capture, options))
                .await
                .context("encoding an update")?;
            if !update.is_empty() {
                return Ok(Some(self.frame_of(&update, Vec::new())));
            }
        }

        if self.lossy.next_due().is_some_and(|at| at <= now) {
            let due = self.lossy.due(now);
            let options = self.encode_options().lossless();
            let region = due.clone();
            let update = self
                .encode(move |encoder| encoder.refresh(&region, options))
                .await
                .context("encoding a lossless refresh")?;
            // Every tile of the region was sent losslessly, whether or not a
            // draw covered it wholly.
            let frame = self.frame_of(&update, Vec::new());
            self.lossy.clear(&due);
            debug!(
                connection_ref = %self.connection_ref,
                tiles = due.tile_count(),
                draws = update.draws.len(),
                "sending lossy areas again losslessly"
            );
            if !update.is_empty() {
                return Ok(Some(frame));
            }
        }
        Ok(None)
    }

    /// Replace the client's surface, if it has one, with a primary surface of
    /// `size`, drawn from `capture`, which is all of it.
    async fn start_surface(
        &mut self,
        size: geometry::Size,
        capture: geometry::Capture,
    ) -> Result<Vec<Vec<u8>>> {
        let mut start = Vec::new();
        if let Some(old) = self.client_surface {
            debug!(
                connection_ref = %self.connection_ref,
                from = %old,
                to = %size,
                "the backend replaced its surface; replacing the client's"
            );
            start.push(message(
                display_server::SURFACE_DESTROY,
                &SurfaceDestroy {
                    surface_id: SURFACE_ID,
                },
            ));
        }
        start.push(message(
            display_server::SURFACE_CREATE,
            &SurfaceCreate {
                surface_id: SURFACE_ID,
                width: size.width,
                height: size.height,
                format: surface_fmt::FMT_32_XRGB,
                flags: SURFACE_FLAGS_PRIMARY,
            },
        ));
        // A new surface starts empty: the client holds nothing the old
        // shadow describes, lossily or not.
        self.encoder.reset();
        self.lossy.reset(size);
        // The start sequence is lossless, so the first picture is exact.
        let options = self.encode_options().lossless();
        let update = self
            .encode(move |encoder| encoder.update(&capture, options))
            .await
            .context("encoding a new surface")?;
        let mut frame = self.frame_of(&update, start);
        if self.client_monitors_config {
            let config = DisplayMonitorsConfig {
                max_allowed: 1,
                heads: vec![DisplayHead {
                    monitor_id: 0,
                    surface_id: SURFACE_ID,
                    width: size.width,
                    height: size.height,
                    x: 0,
                    y: 0,
                    flags: 0,
                }],
            };
            // MARK ends the frame, so the monitor goes before it.
            let mark = frame.pop();
            frame.push(message(display_server::MONITORS_CONFIG, &config));
            frame.extend(mark);
        }
        self.client_surface = Some(size);
        self.restart = false;
        info!(
            connection_ref = %self.connection_ref,
            %size,
            "sending the client a new primary surface"
        );
        Ok(frame)
    }

    /// `prefix`, then `update`'s draws, then `MARK`, recording which tiles
    /// the draws leave lossy or exact.
    fn frame_of(&mut self, update: &Update, mut prefix: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
        for draw in &update.draws {
            prefix.push(make_message(display_server::DRAW_COPY, &draw.body));
        }
        self.lossy.record(&update.draws, Instant::now());
        prefix.push(make_message(display_server::MARK, &[]));
        prefix
    }

    /// Run `f` on the encoder on the blocking pool, since comparing and
    /// encoding are CPU-bound, and put the encoder back. As in andris, the
    /// encoder moves into the task; if the task fails, it is lost, the
    /// failure ends the channel, and the default left behind is never used.
    async fn encode<R: Send + 'static>(
        &mut self,
        f: impl FnOnce(&mut UpdateEncoder) -> Result<R> + Send + 'static,
    ) -> Result<R> {
        let mut encoder = std::mem::take(&mut self.encoder);
        let (encoder, result) = tokio::task::spawn_blocking(move || {
            let result = f(&mut encoder);
            (encoder, result)
        })
        .await
        .context("the encoding task failed")?;
        self.encoder = encoder;
        result
    }
}

#[cfg(test)]
mod tests;
