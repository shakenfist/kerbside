//! The backend half: ryll's renderer decoding the hypervisor's display
//! channel.
//!
//! [`start`] hands the backend `SpiceStream` to ryll's `DisplayChannel`,
//! running on a task of its own. The renderer sends `DISPLAY_INIT`, answers
//! spice-server's `SET_ACK` and `PING` at LAN speed, asks for LZ4 images
//! (`PREFERRED_COMPRESSION`), and decodes every draw into a
//! `ChannelEvent`, which it queues for the transcoder to apply to its
//! surface mirror. Its codec preference message is harmless: the backend
//! link carries no `CODEC_*` capability, so spice-server creates no video
//! encoder whatever it says (see [`super::BACKEND_DISPLAY_CAPS`]).
//!
//! The renderer leaves out what it cannot draw (ROP3, stroke, text and
//! composite draws, palette, surface and JPEG-with-alpha images, and draws
//! on off-screen surfaces, which it never composites) with nothing more
//! than a warning of its own, so the transcoder cannot see them in its
//! events. [`Tap`] watches the messages the renderer reads, through the
//! renderer's traffic hook, and reports each of those it finds: once a
//! session in the log, and every time in the
//! `kerbside_proxy_transcode_unsupported_total` metric. A session that
//! meets them shows stale regions where they drew; it cannot fall back to
//! the relay by then, because the client has already been sent the
//! transcoder's own surface.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::Result;
use shakenfist_spice_protocol::constants::image_compression;
use shakenfist_spice_protocol::link::{H264Offer, SpiceStream};
use shakenfist_spice_protocol::messages::{DrawBase, WireType};
use shakenfist_spice_protocol::reader::BoundedReader;
use shakenfist_spice_protocol::{display_server, ImageType};
use shakenfist_spice_renderer::channels::{DisplayChannel, EventSink};
use shakenfist_spice_renderer::{
    ByteCounter, ChannelEvent, DisplaySnapshot, LogConfig, MmClock, TrafficSink,
};
use tokio::sync::{mpsc, Notify};
use tokio::task::JoinHandle;
use tracing::warn;

/// How many decoded events may queue between the renderer and the
/// transcoder. When the queue is full the renderer stops reading the
/// backend, and TCP pushes back on spice-server.
const EVENT_QUEUE: usize = 1024;

/// The renderer's pixmap cache, in bytes: ryll's default.
const IMAGE_CACHE_BYTES: usize = 256 * 1024 * 1024;

/// The renderer's GLZ dictionary, in bytes. The backend is asked for LZ4,
/// so GLZ images should never arrive; this only bounds the dictionary if
/// they do.
const GLZ_DICTIONARY_BYTES: usize = 64 * 1024 * 1024;

/// The renderer's display channel id, and so the display channel id in the
/// key of every surface it creates in the mirror.
pub const RENDERER_CHANNEL_ID: u8 = 0;

/// The backend half of one transcoding display channel.
pub struct Backend {
    /// The renderer's decoded events, in order.
    pub events: mpsc::Receiver<ChannelEvent>,
    /// The renderer's task. It ends when the backend closes the channel or
    /// fails; aborting it closes the backend socket.
    pub task: JoinHandle<Result<()>>,
}

/// Start ryll's renderer on `stream`, a linked backend display channel,
/// reporting what it cannot draw to `tap`.
pub fn start(stream: SpiceStream, tap: Arc<Tap>) -> Backend {
    let (tx, events) = mpsc::channel(EVENT_QUEUE);
    // The transcoder waits on the queue itself, so the wake-up the renderer
    // pairs with each event has no listener.
    let sink = EventSink::new(tx, Arc::new(Notify::new()));
    let mut channel = DisplayChannel::new(
        RENDERER_CHANNEL_ID,
        stream,
        sink,
        None,
        Arc::new(ByteCounter::new()),
        tap,
        Arc::new(Mutex::new(DisplaySnapshot::default())),
        DisplayChannel::new_shared_glz_dictionary(GLZ_DICTIONARY_BYTES),
        LogConfig::default(),
        Arc::new(MmClock::new()),
        H264Offer::Off,
        IMAGE_CACHE_BYTES,
        image_compression::LZ4,
    );
    let task = tokio::spawn(async move { channel.run().await });
    Backend { events, task }
}

/// Something the backend sent that the renderer does not draw.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Unsupported {
    /// `DRAW_ROP3`.
    Rop3,
    /// `DRAW_STROKE`.
    Stroke,
    /// `DRAW_TEXT`.
    Text,
    /// `DRAW_COMPOSITE`.
    Composite,
    /// A draw on, or the creation of, a surface other than the primary.
    OffscreenSurface,
    /// An image whose type the renderer does not decode: `LZ_PLT`,
    /// `SURFACE` or `JPEG_ALPHA`.
    ImageType,
    /// `STREAM_CREATE`, which a backend dialled with no codec capability
    /// should never send.
    Stream,
}

impl Unsupported {
    /// The metric label.
    pub fn label(self) -> &'static str {
        match self {
            Self::Rop3 => "draw_rop3",
            Self::Stroke => "draw_stroke",
            Self::Text => "draw_text",
            Self::Composite => "draw_composite",
            Self::OffscreenSurface => "offscreen_surface",
            Self::ImageType => "image_type",
            Self::Stream => "stream",
        }
    }
}

/// What, if anything, in the display message `msg_type` with body `body`
/// the renderer does not draw.
pub fn classify(msg_type: u16, body: &[u8]) -> Option<Unsupported> {
    match msg_type {
        display_server::DRAW_ROP3 => return Some(Unsupported::Rop3),
        display_server::DRAW_STROKE => return Some(Unsupported::Stroke),
        display_server::DRAW_TEXT => return Some(Unsupported::Text),
        display_server::DRAW_COMPOSITE => return Some(Unsupported::Composite),
        display_server::STREAM_CREATE => return Some(Unsupported::Stream),
        // SURFACE_CREATE opens with the surface id.
        display_server::SURFACE_CREATE => {
            return match body.get(..4) {
                Some(id) if id != [0; 4] => Some(Unsupported::OffscreenSurface),
                _ => None,
            };
        }
        _ => {}
    }
    let draw = matches!(
        msg_type,
        display_server::COPY_BITS | display_server::DRAW_FILL..=display_server::DRAW_ALPHA_BLEND
    );
    if !draw {
        return None;
    }
    let mut reader = BoundedReader::new(body);
    let base = DrawBase::read(&mut reader).ok()?;
    if base.surface_id != 0 {
        return Some(Unsupported::OffscreenSurface);
    }
    // The source image's offset, from the start of the body, follows the
    // draw base: at once for copy, opaque, blend and transparent draws, and
    // after the alpha flags and the alpha for an alpha blend (spice.proto).
    let after_base = body.len() - reader.remaining();
    let offset_at = match msg_type {
        display_server::DRAW_COPY
        | display_server::DRAW_OPAQUE
        | display_server::DRAW_BLEND
        | display_server::DRAW_TRANSPARENT => after_base,
        display_server::DRAW_ALPHA_BLEND => after_base + 2,
        _ => return None,
    };
    let offset = u32::from_le_bytes(body.get(offset_at..offset_at + 4)?.try_into().ok()?);
    // An image descriptor is its id (u64), then its type (u8).
    let image_type = *body.get(usize::try_from(offset).ok()?.checked_add(8)?)?;
    match ImageType::from_u8(image_type) {
        Some(ImageType::LzPalette | ImageType::Surface | ImageType::JpegAlpha) => {
            Some(Unsupported::ImageType)
        }
        _ => None,
    }
}

/// Watches the messages the renderer reads from the backend for what it
/// cannot draw. It is the renderer's traffic hook, which sees each message
/// before the renderer handles it.
pub struct Tap {
    connection_ref: String,
    started: Instant,
    /// What this session has already logged.
    logged: Mutex<HashSet<Unsupported>>,
}

impl Tap {
    pub fn new(connection_ref: &str) -> Self {
        Self {
            connection_ref: connection_ref.to_string(),
            started: Instant::now(),
            logged: Mutex::new(HashSet::new()),
        }
    }

    /// Report `found`: count it, and log it the first time this session.
    fn report(&self, found: Unsupported, msg_name: &str) {
        crate::metrics::inc_transcode_unsupported(found.label());
        let first = self
            .logged
            .lock()
            .expect("transcode tap mutex poisoned")
            .insert(found);
        if first {
            warn!(
                connection_ref = %self.connection_ref,
                kind = found.label(),
                message = msg_name,
                "the transcoder cannot draw what the backend sent; the client will show a \
                 stale region (logged once a session; see \
                 kerbside_proxy_transcode_unsupported_total)"
            );
        }
    }
}

impl TrafficSink for Tap {
    fn record_sent(
        &self,
        _channel: &'static str,
        _msg_type: u16,
        _msg_name: &'static str,
        _raw: &[u8],
    ) {
    }

    fn record_received(
        &self,
        _channel: &'static str,
        msg_type: u16,
        msg_name: &'static str,
        raw: &[u8],
    ) {
        // `raw` holds the 6-byte mini header, then the body.
        let body = raw.get(6..).unwrap_or_default();
        if let Some(found) = classify(msg_type, body) {
            self.report(found, msg_name);
        }
    }

    fn elapsed(&self) -> Duration {
        self.started.elapsed()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shakenfist_spice_protocol::messages::{Clip, Rect};

    /// A draw body on `surface_id` whose source image has type
    /// `image_type`, with `extra` bytes between the draw base and the image
    /// offset (2 for an alpha blend).
    fn draw_body(surface_id: u32, extra: usize, image_type: u8) -> Vec<u8> {
        let mut body = Vec::new();
        DrawBase {
            surface_id,
            bbox: Rect {
                top: 0,
                left: 0,
                bottom: 8,
                right: 8,
            },
            clip: Clip::none(),
        }
        .write(&mut body);
        body.extend(std::iter::repeat_n(0, extra));
        let offset = (body.len() + 4 + 16) as u32;
        body.extend_from_slice(&offset.to_le_bytes());
        body.extend_from_slice(&[0; 16]);
        body.extend_from_slice(&7u64.to_le_bytes());
        body.push(image_type);
        body.extend_from_slice(&[0; 9]);
        body
    }

    #[test]
    fn unimplemented_draws_are_unsupported() {
        assert_eq!(
            classify(display_server::DRAW_ROP3, &[]),
            Some(Unsupported::Rop3)
        );
        assert_eq!(
            classify(display_server::DRAW_STROKE, &[]),
            Some(Unsupported::Stroke)
        );
        assert_eq!(
            classify(display_server::DRAW_TEXT, &[]),
            Some(Unsupported::Text)
        );
        assert_eq!(
            classify(display_server::DRAW_COMPOSITE, &[]),
            Some(Unsupported::Composite)
        );
        assert_eq!(
            classify(display_server::STREAM_CREATE, &[]),
            Some(Unsupported::Stream)
        );
        assert_eq!(classify(display_server::MARK, &[]), None);
    }

    #[test]
    fn draws_off_the_primary_surface_are_unsupported() {
        let lz4 = ImageType::Lz4 as u8;
        assert_eq!(
            classify(display_server::DRAW_COPY, &draw_body(0, 0, lz4)),
            None
        );
        assert_eq!(
            classify(display_server::DRAW_COPY, &draw_body(3, 0, lz4)),
            Some(Unsupported::OffscreenSurface)
        );
        assert_eq!(
            classify(display_server::DRAW_FILL, &draw_body(1, 0, lz4)),
            Some(Unsupported::OffscreenSurface)
        );
        assert_eq!(
            classify(display_server::SURFACE_CREATE, &[0, 0, 0, 0, 9, 9]),
            None
        );
        assert_eq!(
            classify(display_server::SURFACE_CREATE, &[2, 0, 0, 0, 9, 9]),
            Some(Unsupported::OffscreenSurface)
        );
    }

    #[test]
    fn undecodable_image_types_are_unsupported() {
        for unsupported in [
            ImageType::LzPalette,
            ImageType::Surface,
            ImageType::JpegAlpha,
        ] {
            assert_eq!(
                classify(
                    display_server::DRAW_COPY,
                    &draw_body(0, 0, unsupported as u8)
                ),
                Some(Unsupported::ImageType),
                "{unsupported:?}"
            );
            assert_eq!(
                classify(
                    display_server::DRAW_ALPHA_BLEND,
                    &draw_body(0, 2, unsupported as u8)
                ),
                Some(Unsupported::ImageType),
                "{unsupported:?} in an alpha blend"
            );
        }
        for decoded in [
            ImageType::Lz4,
            ImageType::Quic,
            ImageType::Jpeg,
            ImageType::Pixmap,
        ] {
            assert_eq!(
                classify(display_server::DRAW_OPAQUE, &draw_body(0, 0, decoded as u8)),
                None,
                "{decoded:?}"
            );
        }
    }

    #[test]
    fn truncated_draws_are_not_reported() {
        let body = draw_body(0, 0, ImageType::Surface as u8);
        assert_eq!(classify(display_server::DRAW_COPY, &body[..30]), None);
        assert_eq!(classify(display_server::DRAW_COPY, &[]), None);
    }

    #[test]
    fn the_tap_counts_every_occurrence() {
        let tap = Tap::new("test-tap");
        let before = crate::metrics::transcode_unsupported("draw_text");
        let mut raw = vec![0; 6];
        raw.extend_from_slice(&[1, 2, 3]);
        tap.record_received("display", display_server::DRAW_TEXT, "draw_text", &raw);
        tap.record_received("display", display_server::DRAW_TEXT, "draw_text", &raw);
        tap.record_received("display", display_server::MARK, "mark", &raw[..6]);
        assert_eq!(
            crate::metrics::transcode_unsupported("draw_text"),
            before + 2
        );
    }
}
