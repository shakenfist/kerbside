//! What the update pipeline's tests share: a desktop they change and
//! capture, and a client that decodes the draws it is sent with ryll's
//! readers and decoders.
//!
//! Copied from andris (https://github.com/shakenfist/andris) at commit
//! e29929fa88bbafebdd1046138112c1a4cfecd2cf, `andris/src/server/updates/test_support.rs`.
//! Changed from the original:
//!
//! - paths into andris's platform layer point at `crate::transcode::geometry`.
//!
//! Keep it otherwise as andris has it, so that the copy can be diffed
//! against andris and either brought up to date or replaced by a shared
//! crate (see `crate::transcode`).

use shakenfist_spice_compression::{decompress_spice_lz4, JpegDecoder, JpegDecoderRsDecoder};
use shakenfist_spice_protocol::constants::{bitmap_flags, bitmap_fmt, clip_type, ropd};
use shakenfist_spice_protocol::messages::{BitmapPalette, DrawCopy, ImagePayload, Rect, WireType};

use super::{Draw, EncodeOptions, Encoding, JpegQuality, Update, UpdateEncoder};
use crate::transcode::geometry::{Capture, Frame, Patch, Rectangle, Size, TILE};

/// 4 x 3 tiles, the last column 36 pixels wide and the last row 8
/// rows tall.
pub const SIZE: Size = Size {
    width: 228,
    height: 136,
};

/// Bytes of padding after each row of a test frame.
pub const PADDING: usize = 12;

pub const LZ4: EncodeOptions = EncodeOptions {
    lz4: true,
    jpeg: None,
};
pub const RAW: EncodeOptions = EncodeOptions {
    lz4: false,
    jpeg: None,
};
/// What `auto-glz` allows, at the default quality.
pub const AUTO: EncodeOptions = EncodeOptions {
    lz4: true,
    jpeg: Some(JpegQuality::DEFAULT),
};
/// JPEG allowed, but not LZ4: a client without the LZ4 capability.
pub const JPEG_ONLY: EncodeOptions = EncodeOptions {
    lz4: false,
    jpeg: Some(JpegQuality::DEFAULT),
};

pub fn size(width: u32, height: u32) -> Size {
    Size { width, height }
}

pub fn rect(x: u32, y: u32, width: u32, height: u32) -> Rectangle {
    Rectangle::new(x, y, width, height)
}

/// The tile holding pixel (`x`, `y`), clipped to `size`.
pub fn tile_of(size: Size, x: u32, y: u32) -> Rectangle {
    rect(x / TILE * TILE, y / TILE * TILE, TILE, TILE)
        .clip(size)
        .unwrap()
}

/// A small xorshift generator, so that tests repeat.
pub struct Rng(pub u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    /// A number below `n`.
    pub fn below(&mut self, n: u32) -> u32 {
        (self.next() % u64::from(n)) as u32
    }
}

/// A desktop the tests change and capture: BGRX with no padding.
#[derive(Clone)]
pub struct Desktop {
    pub size: Size,
    pub pixels: Vec<u8>,
}

impl Desktop {
    /// Soft diagonal stripes, which LZ4 shrinks.
    pub fn pattern(size: Size) -> Self {
        let mut pixels = Vec::with_capacity(size.width as usize * size.height as usize * 4);
        for y in 0..size.height {
            for x in 0..size.width {
                let v = ((x + y) / 16 % 4) as u8 * 60;
                pixels.extend_from_slice(&[v, 255 - v, v / 2, 0]);
            }
        }
        Self { size, pixels }
    }

    /// Something like a photograph: smooth gradients and slow waves,
    /// with a little grain, which LZ4 cannot shrink much and JPEG
    /// can.
    pub fn photo(size: Size) -> Self {
        let mut rng = Rng(0x5EED_0F0F_F070_0001);
        let mut pixels = Vec::with_capacity(size.width as usize * size.height as usize * 4);
        for y in 0..size.height {
            for x in 0..size.width {
                let (fx, fy) = (f64::from(x), f64::from(y));
                let wave = 40.0 * (fx / 23.0).sin() * (fy / 31.0).cos();
                let mut pixel = [0; 4];
                for (channel, base) in [(0, 60.0), (1, 110.0), (2, 160.0)] {
                    let grain = f64::from(rng.below(13)) - 6.0;
                    let value = base + fx * 0.2 + fy * 0.15 + wave + grain;
                    pixel[channel] = value.clamp(0.0, 255.0) as u8;
                }
                pixels.extend_from_slice(&pixel);
            }
        }
        Self { size, pixels }
    }

    /// Something like text: dark glyph strokes, one or two pixels
    /// wide, in 8 x 16 cells on a flat light background.
    pub fn text(size: Size) -> Self {
        let mut desktop = Self {
            size,
            pixels: [0xF0, 0xF0, 0xF0, 0].repeat(size.width as usize * size.height as usize),
        };
        let mut rng = Rng(0x7E47_7E47_7E47_7E47);
        let ink = [0x20, 0x20, 0x20, 0];
        for top in (0..size.height.saturating_sub(16)).step_by(16) {
            for left in (0..size.width.saturating_sub(8)).step_by(8) {
                // Some cells are spaces.
                if rng.below(5) == 0 {
                    continue;
                }
                for _ in 0..3 {
                    let stroke = if rng.below(2) == 0 {
                        rect(left + 1 + rng.below(5), top + 3, 1 + rng.below(2), 10)
                    } else {
                        rect(left + 1, top + 3 + rng.below(9), 6, 1 + rng.below(2))
                    };
                    desktop.fill(stroke, ink);
                }
            }
        }
        desktop
    }

    /// Pseudo-random pixels, which LZ4 cannot shrink.
    pub fn noise(size: Size) -> Self {
        let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
        let pixels = (0..size.width * size.height * 4)
            .map(|_| rng.next() as u8)
            .collect();
        Self { size, pixels }
    }

    pub fn at(&self, x: u32, y: u32) -> usize {
        (y as usize * self.size.width as usize + x as usize) * 4
    }

    /// Paint `area`, clipped to the desktop, with `bgrx`.
    pub fn fill(&mut self, area: Rectangle, bgrx: [u8; 4]) {
        let area = area.clip(self.size).unwrap();
        for y in area.y..area.y + area.height {
            for x in area.x..area.x + area.width {
                let at = self.at(x, y);
                self.pixels[at..at + 4].copy_from_slice(&bgrx);
            }
        }
    }

    /// Invert pixel (`x`, `y`)'s colour, so that it surely changes.
    pub fn flip(&mut self, x: u32, y: u32) {
        let at = self.at(x, y);
        for byte in &mut self.pixels[at..at + 3] {
            *byte = !*byte;
        }
    }

    /// `area`'s pixels as a frame whose rows carry [`PADDING`] bytes
    /// of `pad`.
    pub fn frame(&self, area: Rectangle, pad: u8) -> Frame {
        let row_bytes = area.width as usize * 4;
        let mut data = Vec::new();
        for y in area.y..area.y + area.height {
            let at = self.at(area.x, y);
            data.extend_from_slice(&self.pixels[at..at + row_bytes]);
            data.extend_from_slice(&[pad; PADDING]);
        }
        Frame::new(area.width, area.height, row_bytes + PADDING, data).unwrap()
    }

    pub fn capture_all(&self) -> Capture {
        Capture::whole(self.frame(Rectangle::full(self.size), 0xAA)).unwrap()
    }

    /// A capture of `rects`, each clipped to the desktop.
    pub fn capture(&self, rects: &[Rectangle]) -> Capture {
        self.capture_padded(rects, 0xAA)
    }

    pub fn capture_padded(&self, rects: &[Rectangle], pad: u8) -> Capture {
        let patches = rects
            .iter()
            .filter_map(|r| r.clip(self.size))
            .map(|r| Patch::new(r, self.frame(r, pad)).unwrap())
            .collect();
        Capture::new(self.size, patches).unwrap()
    }
}

/// BGRX to RGBA with opaque alpha, as the LZ4 decoder produces.
pub fn rgba(bgrx: &[u8]) -> Vec<u8> {
    bgrx.as_chunks::<4>()
        .0
        .iter()
        .flat_map(|p| [p[2], p[1], p[0], 255])
        .collect()
}

/// What the client's surface holds, as RGBA, drawn from the draws it
/// was sent.
pub struct Client {
    pub size: Size,
    pub rgba: Vec<u8>,
}

impl Client {
    pub fn new(size: Size) -> Self {
        Self {
            size,
            rgba: vec![0; size.width as usize * size.height as usize * 4],
        }
    }

    /// Decode `draw` with ryll's reader and decoders, checking every
    /// field andris fixes, and put its image on the surface.
    pub fn apply(&mut self, draw: &Draw) {
        let decoded = DrawCopy::decode(&draw.body).unwrap();
        let r = draw.rect;
        let (w, h) = (r.width as i32, r.height as i32);
        assert!(
            r.lies_within(self.size),
            "{r} is off a {} surface",
            self.size
        );
        assert_eq!(decoded.base.surface_id, 0);
        assert_eq!(
            decoded.base.bbox,
            Rect {
                top: r.y as i32,
                left: r.x as i32,
                bottom: r.y as i32 + h,
                right: r.x as i32 + w,
            }
        );
        assert_eq!(decoded.base.clip.clip_type, clip_type::NONE);
        assert_eq!(
            decoded.src_area,
            Rect {
                top: 0,
                left: 0,
                bottom: h,
                right: w,
            }
        );
        assert_eq!(decoded.rop_descriptor, ropd::OP_PUT);
        assert_eq!(decoded.scale_mode, 0);
        assert_eq!(decoded.mask.flags, 0);
        assert!(decoded.mask.bitmap.is_none());

        let image = decoded.src_bitmap.unwrap();
        let descriptor = &image.descriptor;
        assert_eq!(descriptor.flags, 0, "no CACHE_ME");
        assert_eq!(
            (descriptor.width, descriptor.height),
            (r.width, r.height),
            "the descriptor is the rectangle's size"
        );
        assert_eq!(descriptor.image_type, draw.encoding.image_type() as u8);
        let pixels = match &image.payload {
            ImagePayload::Lz4(data) => {
                assert_eq!(draw.encoding, Encoding::Lz4);
                decompress_spice_lz4(&data.data, r.width as usize, r.height as usize)
                    .unwrap()
                    .pixels
            }
            ImagePayload::Jpeg(data) => {
                assert_eq!(draw.encoding, Encoding::Jpeg);
                let decoded = decode_jpeg(&data.data);
                assert_eq!(
                    (decoded.width, decoded.height),
                    (r.width, r.height),
                    "the JPEG is the rectangle's size"
                );
                decoded.rgba
            }
            ImagePayload::Bitmap(bitmap) => {
                assert_eq!(draw.encoding, Encoding::Bitmap);
                assert_eq!(bitmap.header.format, bitmap_fmt::BIT32);
                assert_eq!(bitmap.header.flags, bitmap_flags::TOP_DOWN);
                assert_eq!((bitmap.header.x, bitmap.header.y), (r.width, r.height));
                assert_eq!(bitmap.header.stride, r.width * 4);
                assert_eq!(bitmap.header.palette, BitmapPalette::None);
                rgba(&bitmap.data)
            }
            other => panic!("unexpected payload {other:?}"),
        };
        let row_bytes = r.width as usize * 4;
        for (row, y) in (r.y..r.y + r.height).enumerate() {
            let at = (y as usize * self.size.width as usize + r.x as usize) * 4;
            self.rgba[at..at + row_bytes]
                .copy_from_slice(&pixels[row * row_bytes..(row + 1) * row_bytes]);
        }
    }

    pub fn apply_all(&mut self, update: &Update) {
        for draw in &update.draws {
            self.apply(draw);
        }
    }

    /// The largest difference between any channel of the surface and
    /// of `desktop`.
    pub fn worst_difference(&self, desktop: &Desktop) -> u8 {
        self.rgba
            .iter()
            .zip(rgba(&desktop.pixels))
            .map(|(&mine, theirs)| mine.abs_diff(theirs))
            .max()
            .unwrap_or(0)
    }

    /// Assert the surface shows exactly `desktop`.
    pub fn assert_shows(&self, desktop: &Desktop) {
        assert_eq!(self.size, desktop.size);
        let row_bytes = self.size.width as usize * 4;
        for y in 0..self.size.height as usize {
            let row = &desktop.pixels[y * row_bytes..(y + 1) * row_bytes];
            assert!(
                self.rgba[y * row_bytes..(y + 1) * row_bytes] == rgba(row)[..],
                "row {y} differs from the desktop"
            );
        }
    }
}

/// A JPEG, decoded with ryll's pure-Rust decoder, after checking that
/// it starts and ends as a JPEG must.
pub fn decode_jpeg(data: &[u8]) -> shakenfist_spice_compression::DecodedJpeg {
    assert!(data.starts_with(&[0xFF, 0xD8]), "no SOI marker");
    assert!(data.ends_with(&[0xFF, 0xD9]), "no EOI marker");
    JpegDecoderRsDecoder::new()
        .decode(data)
        .expect("the JPEG does not decode")
}

/// An encoder, and a client that has drawn `desktop`'s first,
/// complete update.
pub fn started(desktop: &Desktop) -> (UpdateEncoder, Client) {
    let mut encoder = UpdateEncoder::new();
    let mut client = Client::new(desktop.size);
    let update = encoder.update(&desktop.capture_all(), LZ4).unwrap();
    client.apply_all(&update);
    client.assert_shows(desktop);
    (encoder, client)
}

pub fn rects(update: &Update) -> Vec<Rectangle> {
    update.draws.iter().map(|draw| draw.rect).collect()
}
