//! Encoding one rectangle of the shadow as a `DRAW_COPY`.
//!
//! Each `DRAW_COPY` draws on surface [`SURFACE_ID`]: the rectangle as the
//! box, no clip, `OP_PUT`, no mask, and one image exactly the rectangle's
//! size, all of which is the source area. The image is, in order of
//! preference:
//!
//! 1. JPEG, when the client may take it ([`EncodeOptions::jpeg`]), the
//!    rectangle [`looks_photographic`], and the JPEG comes to at most
//!    [`JPEG_MAX_PERCENT`] of what lossless would send;
//! 2. LZ4, when the client may take LZ4 and the result is smaller than
//!    the raw pixels;
//! 3. an uncompressed top-down 32-bit `BITMAP`.
//!
//! The classifier's thresholds were chosen from measurements of real
//! screens; each constant says what they showed. JPEG is never sent with
//! alpha. Each [`Encoding`] says whether it is lossy, and only JPEG is:
//! [`LossyTiles`] tracks where the client holds JPEG's approximation, so
//! that it can be sent again losslessly once it stops changing. Image ids
//! count from 1, and no image asks to be cached.
//!
//! [`LossyTiles`]: super::LossyTiles
//!
//! Copied from andris (https://github.com/shakenfist/andris) at commit
//! e29929fa88bbafebdd1046138112c1a4cfecd2cf, `andris/src/server/updates/encode.rs`.
//! Changed from the original:
//!
//! - let-chains are rewritten as nested `if let`s, because this crate is
//!   edition 2021, not 2024;
//! - paths into andris's platform layer point at `crate::transcode::geometry`,
//!   and the JPEG quality flag in the docs is the transcoder's own.
//!
//! Keep it otherwise as andris has it, so that the copy can be diffed
//! against andris and either brought up to date or replaced by a shared
//! crate (see `crate::transcode`).

use anyhow::{Context, Result};
use shakenfist_spice_compression::{encode_spice_jpeg, encode_spice_lz4, Bgrx};
use shakenfist_spice_protocol::constants::{bitmap_flags, bitmap_fmt, ropd};
use shakenfist_spice_protocol::messages::{
    BinaryData, BitmapHeader, BitmapPalette, BitmapPayload, Clip, DrawBase, DrawCopyBuilder,
    ImageDescriptor, ImagePayload, Rect, SpiceImage,
};
use shakenfist_spice_protocol::ImageType;

use super::shadow::Shadow;
use super::Draw;
use crate::transcode::geometry::{Rectangle, TILE};

/// The surface every update draws on: the primary surface.
pub const SURFACE_ID: u32 = 0;

/// The smallest rectangle, in pixels, that may be sent as JPEG: one
/// whole [`TILE`].
///
/// Measured with `andris/tests/jpeg_corpus.rs` on a corpus of real
/// screens, photographic content gains plenty at one tile: the JPEG at
/// quality 85 of a 64 x 64 photo tile is under a tenth of its LZ4.
/// Rectangles are tile-merged, so anything smaller is a tile clipped by
/// the surface's edge, and stays lossless.
pub const JPEG_MIN_AREA: u64 = TILE as u64 * TILE as u64;

/// The shortest side of a rectangle that may be sent as JPEG: one 4:2:0
/// MCU. A thinner strip is mostly padding.
pub const JPEG_MIN_SIDE: u32 = 16;

/// A rectangle is tried as JPEG only if its LZ4 encoding is more than
/// this percentage of its raw bytes: LZ4 saves less than half.
///
/// This is the classifier's signal. In the corpus every 64 x 64 tile of
/// text, whether a terminal, a document or a real desktop, came out
/// under 30%, and almost all under 20%; photographs came out at 40% to
/// 100%, with 1% of their tiles under 50%. Smooth gradients came out at
/// 10% to 40%, overlapping the text, so no threshold separates them, and
/// they stay lossless, where LZ4 already takes them to a fifth or less.
/// 50% keeps the widest margin from text, where a JPEG would smear
/// glyphs, for the cost of that 1% of photo tiles going as LZ4. The size
/// test that follows cannot stand in for this one: JPEG was the smaller
/// for 43% of the real desktop's tiles, and for a whole terminal.
pub const JPEG_MIN_LZ4_PERCENT: u64 = 50;

/// A JPEG is sent only if it is at most this percentage of what lossless
/// would send.
///
/// An area sent as JPEG is sent again losslessly once still, so a JPEG
/// that saves little costs more than it gains. In the corpus the JPEG of
/// a photograph came to 3% to 9% of its LZ4, by rectangle size, and
/// this limit turned none away; it bounds the waste on content the
/// classifier misjudges.
pub const JPEG_MAX_PERCENT: u64 = 50;

/// A JPEG quality, 1 to 100: `--transcode-jpeg-quality` when it is not 0.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JpegQuality(u8);

impl JpegQuality {
    /// `--transcode-jpeg-quality`'s default, and spice-server's.
    pub const DEFAULT: Self = Self(85);

    /// The quality `quality`, or `None` unless it is 1 to 100.
    pub const fn new(quality: u8) -> Option<Self> {
        if matches!(quality, 1..=100) {
            Some(Self(quality))
        } else {
            None
        }
    }

    /// The quality, 1 to 100.
    pub const fn get(self) -> u8 {
        self.0
    }
}

/// What the client may be sent, as far as encoding goes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct EncodeOptions {
    /// Whether images may be LZ4.
    pub lz4: bool,
    /// The quality to encode a photographic rectangle as JPEG at, or
    /// `None` if images must be lossless.
    pub jpeg: Option<JpegQuality>,
}

impl EncodeOptions {
    /// These options with JPEG ruled out: for a lossless refresh.
    pub fn lossless(self) -> Self {
        Self { jpeg: None, ..self }
    }
}

/// How one draw's image is encoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encoding {
    /// LZ4-compressed BGRX.
    Lz4,
    /// An uncompressed top-down 32-bit `BITMAP`.
    Bitmap,
    /// A baseline JPEG, with no alpha.
    Jpeg,
}

impl Encoding {
    /// Whether the client's pixels may differ from the shadow's once the
    /// image is drawn: only for JPEG.
    pub fn is_lossy(self) -> bool {
        match self {
            Self::Lz4 | Self::Bitmap => false,
            Self::Jpeg => true,
        }
    }

    /// The SPICE image type this encoding is sent as.
    pub(super) fn image_type(self) -> ImageType {
        match self {
            Self::Lz4 => ImageType::Lz4,
            Self::Bitmap => ImageType::Pixmap,
            Self::Jpeg => ImageType::Jpeg,
        }
    }
}

/// `rect` in pieces of whole rows, top first, each at most `max_bytes`
/// raw, or one row a piece if a row is larger. When a piece may be at
/// least [`TILE`] rows, its height is a whole number of tiles, so that a
/// tile-aligned rectangle splits into tile-aligned pieces and no tile is
/// sent half in one piece and half in another.
pub(super) fn split(rect: Rectangle, max_bytes: usize) -> impl Iterator<Item = Rectangle> {
    let row_bytes = (rect.width as usize * 4).max(1);
    let mut rows = u32::try_from(max_bytes / row_bytes)
        .unwrap_or(u32::MAX)
        .max(1);
    if rows >= TILE {
        rows -= rows % TILE;
    }
    (0..rect.height.div_ceil(rows)).map(move |index| {
        // index * rows < height, so neither overflows.
        let top = index * rows;
        Rectangle::new(
            rect.x,
            rect.y + top,
            rect.width,
            rows.min(rect.height - top),
        )
    })
}

/// A rectangle in SPICE's wire form.
pub(super) fn wire_rect(rect: Rectangle) -> Result<Rect> {
    let as_i32 = |v: u64| i32::try_from(v).context("a coordinate does not fit in an i32");
    Ok(Rect {
        top: as_i32(u64::from(rect.y))?,
        left: as_i32(u64::from(rect.x))?,
        bottom: as_i32(rect.bottom())?,
        right: as_i32(rect.right())?,
    })
}

/// Whether a `width` x `height` image whose LZ4 encoding is `lz4_len`
/// bytes looks photographic enough to try as JPEG: large enough, and
/// LZ4 leaves more than [`JPEG_MIN_LZ4_PERCENT`] of its raw bytes.
pub fn looks_photographic(width: u32, height: u32, lz4_len: usize) -> bool {
    let area = u64::from(width) * u64::from(height);
    let raw_len = area * 4;
    width.min(height) >= JPEG_MIN_SIDE
        && area >= JPEG_MIN_AREA
        && (lz4_len as u64).saturating_mul(100) > raw_len * JPEG_MIN_LZ4_PERCENT
}

/// Choose how to encode `image`, and encode it.
///
/// - JPEG if `options` allow it, the image [`looks_photographic`], and
///   the JPEG is at most [`JPEG_MAX_PERCENT`] of what lossless would
///   send. The LZ4 the classifier needs is made whether or not LZ4 may
///   be sent.
/// - Otherwise LZ4 if `options` allow it and it comes out smaller than
///   the raw pixels.
/// - Otherwise a top-down 32-bit `BITMAP` with no row padding.
fn choose_encoding(image: &Bgrx<'_>, options: EncodeOptions) -> Result<(Encoding, ImagePayload)> {
    let row_bytes = image.width() as usize * 4;
    let raw_len = row_bytes * image.height() as usize;
    let lz4 = (options.lz4 || options.jpeg.is_some()).then(|| encode_spice_lz4(image));
    if let (Some(quality), Some(lz4)) = (options.jpeg, &lz4) {
        if looks_photographic(image.width(), image.height(), lz4.len()) {
            let lossless_len = if options.lz4 {
                lz4.len().min(raw_len)
            } else {
                raw_len
            };
            let data = encode_spice_jpeg(image, quality.get())
                .with_context(|| format!("encoding a {}x{} JPEG", image.width(), image.height()))?;
            if data.len() as u64 * 100 <= lossless_len as u64 * JPEG_MAX_PERCENT {
                return Ok((Encoding::Jpeg, ImagePayload::Jpeg(BinaryData { data })));
            }
        }
    }
    if options.lz4 {
        if let Some(data) = lz4 {
            if data.len() < raw_len {
                return Ok((Encoding::Lz4, ImagePayload::Lz4(BinaryData { data })));
            }
        }
    }
    let mut data = Vec::with_capacity(raw_len);
    for row in image
        .data()
        .chunks(image.stride())
        .take(image.height() as usize)
    {
        data.extend_from_slice(row.get(..row_bytes).context("an image row is short")?);
    }
    let header = BitmapHeader {
        format: bitmap_fmt::BIT32,
        flags: bitmap_flags::TOP_DOWN,
        x: image.width(),
        y: image.height(),
        stride: u32::try_from(row_bytes).context("an image row is too wide")?,
        palette: BitmapPalette::None,
    };
    Ok((
        Encoding::Bitmap,
        ImagePayload::Bitmap(BitmapPayload { header, data }),
    ))
}

/// The `DRAW_COPY` that puts `rect` of `shadow` on the surface, its image
/// carrying id `image_id`.
pub(super) fn encode_draw(
    shadow: &Shadow,
    rect: Rectangle,
    image_id: u64,
    options: EncodeOptions,
) -> Result<Draw> {
    let image = shadow.image(rect)?;
    let (encoding, payload) = choose_encoding(&image, options)?;
    let image = SpiceImage {
        descriptor: ImageDescriptor {
            image_id,
            image_type: encoding.image_type() as u8,
            flags: 0,
            width: rect.width,
            height: rect.height,
        },
        payload,
    };
    let base = DrawBase {
        surface_id: SURFACE_ID,
        bbox: wire_rect(rect)?,
        clip: Clip::none(),
    };
    let src_area = wire_rect(Rectangle::new(0, 0, rect.width, rect.height))?;
    let body = DrawCopyBuilder::new(&base, &image, src_area)
        .rop_descriptor(ropd::OP_PUT)
        .build();
    Ok(Draw {
        rect,
        encoding,
        body,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transcode::updates::test_support::*;
    use crate::transcode::updates::UpdateEncoder;

    #[test]
    fn split_cuts_whole_rows_within_the_limit() {
        let r = rect(3, 5, 10, 25);
        // 40 bytes a row: 10 rows a piece.
        assert_eq!(
            split(r, 400).collect::<Vec<_>>(),
            vec![rect(3, 5, 10, 10), rect(3, 15, 10, 10), rect(3, 25, 10, 5)]
        );
        assert_eq!(split(r, 1000).collect::<Vec<_>>(), vec![r], "exactly fits");
        assert_eq!(split(r, 999).count(), 2, "one byte over");
        assert_eq!(split(r, 10).count(), 25, "a row each when a row is over");
        assert_eq!(split(rect(0, 0, 10, 0), 400).count(), 0);
        // 100 rows fit, but pieces are whole tiles.
        assert_eq!(
            split(rect(0, 64, 1, 200), 400).collect::<Vec<_>>(),
            vec![
                rect(0, 64, 1, 64),
                rect(0, 128, 1, 64),
                rect(0, 192, 1, 64),
                rect(0, 256, 1, 8)
            ]
        );
    }

    #[test]
    fn lz4_only_when_allowed_and_smaller() {
        let desktop = Desktop::pattern(SIZE);
        let mut client = Client::new(SIZE);
        let update = UpdateEncoder::new()
            .update(&desktop.capture_all(), LZ4)
            .unwrap();
        assert_eq!(update.draws[0].encoding, Encoding::Lz4);
        assert!(update.encoded_bytes() < update.raw_bytes());
        client.apply_all(&update);
        client.assert_shows(&desktop);

        let update = UpdateEncoder::new()
            .update(&desktop.capture_all(), RAW)
            .unwrap();
        assert_eq!(update.draws[0].encoding, Encoding::Bitmap);
        client.apply_all(&update);
        client.assert_shows(&desktop);

        let noise = Desktop::noise(SIZE);
        let update = UpdateEncoder::new()
            .update(&noise.capture_all(), LZ4)
            .unwrap();
        assert_eq!(update.draws[0].encoding, Encoding::Bitmap);
        client.apply_all(&update);
        client.assert_shows(&noise);

        assert!(!Encoding::Lz4.is_lossy());
        assert!(!Encoding::Bitmap.is_lossy());
        assert!(Encoding::Jpeg.is_lossy());
    }

    /// The encodings of the draws of `desktop`'s first, complete update,
    /// encoded under `options`.
    fn first_encodings(desktop: &Desktop, options: EncodeOptions) -> Vec<Encoding> {
        UpdateEncoder::new()
            .update(&desktop.capture_all(), options)
            .unwrap()
            .draws
            .iter()
            .map(|draw| draw.encoding)
            .collect()
    }

    #[test]
    fn jpeg_quality_is_one_to_one_hundred() {
        assert_eq!(JpegQuality::new(0), None);
        assert_eq!(JpegQuality::new(1).map(JpegQuality::get), Some(1));
        assert_eq!(JpegQuality::new(100).map(JpegQuality::get), Some(100));
        assert_eq!(JpegQuality::new(101), None);
        assert_eq!(JpegQuality::DEFAULT.get(), 85);
        assert_eq!(AUTO.lossless(), LZ4);
    }

    #[test]
    fn a_photographic_rectangle_is_jpeg_when_allowed() {
        let desktop = Desktop::photo(size(160, 128));
        for options in [AUTO, JPEG_ONLY] {
            let update = UpdateEncoder::new()
                .update(&desktop.capture_all(), options)
                .unwrap();
            assert_eq!(rects(&update), vec![Rectangle::full(desktop.size)]);
            let draw = &update.draws[0];
            assert_eq!(draw.encoding, Encoding::Jpeg, "{options:?}");
            assert!(draw.is_lossy());
            // Far smaller than lossless would have been.
            assert!(draw.encoded_bytes() * 4 < draw.raw_bytes());

            // It decodes to the rectangle's size, and close to the desktop.
            let mut client = Client::new(desktop.size);
            client.apply_all(&update);
            let worst = client.worst_difference(&desktop);
            assert!(worst > 0, "a JPEG of this is not exact");
            assert!(worst < 64, "the JPEG is off by {worst}");
        }
    }

    #[test]
    fn a_photographic_rectangle_is_lossless_unless_allowed() {
        let desktop = Desktop::photo(size(160, 128));
        // lz4 is an explicit choice, OFF is RAW, and a JPEG quality of 0 is
        // LZ4 with no JPEG: none of them is ever JPEG.
        for options in [LZ4, RAW] {
            let update = UpdateEncoder::new()
                .update(&desktop.capture_all(), options)
                .unwrap();
            assert!(update.draws.iter().all(|draw| !draw.is_lossy()));
            let mut client = Client::new(desktop.size);
            client.apply_all(&update);
            client.assert_shows(&desktop);
        }
    }

    #[test]
    fn text_is_never_jpeg() {
        let desktop = Desktop::text(size(512, 384));
        for options in [AUTO, JPEG_ONLY] {
            let encodings = first_encodings(&desktop, options);
            assert!(
                !encodings.contains(&Encoding::Jpeg),
                "{options:?}: {encodings:?}"
            );
        }
        // Tile by tile too, as a frame of small changes would send it.
        let (mut encoder, mut client) = started(&desktop);
        let mut changed = desktop.clone();
        for row in 0..6 {
            for col in 0..8 {
                changed.flip(col * TILE + 9, row * TILE + 9);
            }
        }
        let update = encoder.update(&changed.capture_all(), AUTO).unwrap();
        assert!(update.draws.iter().all(|draw| !draw.is_lossy()));
        client.apply_all(&update);
        client.assert_shows(&changed);
    }

    #[test]
    fn small_rectangles_are_never_jpeg() {
        // Under a tile's area, or too thin, however photographic.
        for small in [size(63, 64), size(64, 63), size(400, 10), size(10, 400)] {
            let desktop = Desktop::photo(small);
            assert_eq!(
                first_encodings(&desktop, AUTO),
                vec![Encoding::Lz4],
                "{small}"
            );
        }
        // A tile clipped by the surface's edge: SIZE's last column is 36
        // pixels wide.
        let mut desktop = Desktop::photo(SIZE);
        let mut encoder = UpdateEncoder::new();
        encoder.update(&desktop.capture_all(), LZ4).unwrap();
        desktop.flip(SIZE.width - 1, 0);
        let update = encoder.update(&desktop.capture_all(), AUTO).unwrap();
        assert_eq!(rects(&update), vec![rect(192, 0, 36, 64)]);
        assert!(!update.draws[0].is_lossy());
        assert!(!looks_photographic(TILE - 1, TILE, usize::MAX));
        assert!(!looks_photographic(4096, JPEG_MIN_SIDE - 1, usize::MAX));
        assert!(looks_photographic(TILE, TILE, usize::MAX));
    }

    #[test]
    fn the_classifier_needs_lz4_to_save_less_than_half() {
        let raw = (TILE * TILE * 4) as usize;
        assert!(!looks_photographic(TILE, TILE, raw / 2));
        assert!(looks_photographic(TILE, TILE, raw / 2 + 1));
    }
}
