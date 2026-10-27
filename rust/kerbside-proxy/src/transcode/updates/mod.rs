//! The update pipeline: from captured pixels to the `DRAW_COPY` bodies
//! that bring the client's surface up to date.
//!
//! # The shadow
//!
//! [`UpdateEncoder`] keeps a *shadow*: the pixels of the whole surface as
//! andris last sent them, which is what the client's surface holds. A
//! capture is compared with the shadow, not with the capture before it,
//! so a change is sent once however it came to be captured.
//!
//! A shadow is made from a complete capture, of the whole desktop, and
//! every tile of that first capture counts as changed: the first frame of
//! a surface is all of it. A capture of another size than the shadow
//! drops it, and must itself be complete. So must the first capture after
//! [`UpdateEncoder::reset`].
//!
//! # From a capture to rectangles
//!
//! 1. Each patch of the capture is compared with the shadow one [`TILE`]
//!    x [`TILE`] tile at a time, a row at a time, over the part of the
//!    tile the patch covers. A patch that covers a tile only in part, such
//!    as a band of rows not aligned to tiles, is compared over that part
//!    alone; the rest of the tile is not looked at.
//! 2. Each part that differs is copied into the shadow, and its tile joins
//!    the changed [`Region`].
//! 3. [`Region::rectangles`] merges the region into at most
//!    [`MAX_RECTS_PER_FRAME`] rectangles. Over that cap its later stages
//!    cover tiles that did not change, or were not captured.
//! 4. A rectangle over [`MAX_DRAW_BYTES`] raw is split by rows into pieces
//!    that fit, so that every message stays far below kerbside's 16 MiB
//!    cap. The pieces are whole tile rows, so every draw covers whole
//!    tiles (clipped to the surface).
//! 5. Each piece is encoded from the shadow as one `DRAW_COPY`.
//!
//! The shadow is brought up to date before anything is encoded, and every
//! piece is encoded from it. A tile the merge covered but that did not
//! change, or was not captured, therefore carries what the client already
//! has, so sending it again is harmless.
//!
//! # Encoding
//!
//! Each piece is sent as JPEG, LZ4 or an uncompressed bitmap; [`encode`]
//! says how one is chosen. Only JPEG is lossy, and [`LossyTiles`] tracks
//! where the client holds its approximation, so that it can be sent
//! again losslessly once it stops changing.
//!
//! # Layout
//!
//! - this module holds [`UpdateEncoder`] and what it produces, [`Update`]
//!   and [`Draw`];
//! - [`shadow`] holds the shadow and compares captures with it;
//! - [`encode`] chooses each draw's encoding and builds its message;
//! - [`lossy`] tracks the tiles sent lossily.
//!
//! This module knows nothing of sockets, so it is tested on its own.
//!
//! Copied from andris (https://github.com/shakenfist/andris) at commit
//! e29929fa88bbafebdd1046138112c1a4cfecd2cf, `andris/src/server/updates/mod.rs`.
//! Changed from the original:
//!
//! - the video stream modules (`heat`, `stream`) and what only they use
//!   (`UpdateEncoder::absorb`) are not copied: the transcoder sends no
//!   streams;
//! - `UpdateEncoder::differences`, which only andris's scrub uses, is not
//!   copied: ryll's surface records the damage of every draw, so there is
//!   nothing for a scrub to catch;
//! - paths into andris's platform layer point at `crate::transcode::geometry`;
//! - the tests of what was not copied, and the test driven by andris's
//!   synthetic desktop, are not copied;
//! - `test_support` is visible to the rest of the transcoder's tests.
//!
//! Keep it otherwise as andris has it, so that the copy can be diffed
//! against andris and either brought up to date or replaced by a shared
//! crate (see `crate::transcode`).
//!
//! [`TILE`]: crate::transcode::geometry::TILE
//! [`Region`]: crate::transcode::geometry::Region
//! [`Region::rectangles`]: crate::transcode::geometry::Region::rectangles

// Items andris uses and the transcoder does not are kept, so the copy
// diffs cleanly against andris.
#![allow(dead_code, unused_imports)]

mod encode;
mod lossy;
mod shadow;
#[cfg(test)]
pub(crate) mod test_support;

use anyhow::{ensure, Context, Result};

use encode::{encode_draw, split};
pub use encode::{
    looks_photographic, EncodeOptions, Encoding, JpegQuality, JPEG_MAX_PERCENT, JPEG_MIN_AREA,
    JPEG_MIN_LZ4_PERCENT, JPEG_MIN_SIDE, SURFACE_ID,
};
pub use lossy::LossyTiles;
use shadow::Shadow;

use crate::transcode::geometry::{Capture, Rectangle, Region, Size};

/// The most rectangles one update merges its changed tiles into, before
/// any is split. Each becomes at least one message, and a client pays a
/// cost per message.
pub const MAX_RECTS_PER_FRAME: usize = 32;

/// The most raw pixel bytes in one `DRAW_COPY`: a larger rectangle is
/// split by rows. A row of the widest desktop is 64 KiB, so a piece is
/// always at least 64 rows.
pub const MAX_DRAW_BYTES: usize = 4 * 1024 * 1024;

/// One `DRAW_COPY`, ready to send.
#[derive(Clone, PartialEq, Eq)]
pub struct Draw {
    /// The part of the surface it draws.
    pub rect: Rectangle,
    /// How its image is encoded.
    pub encoding: Encoding,
    /// The `DRAW_COPY` message body.
    pub body: Vec<u8>,
}

impl Draw {
    /// Whether the client's pixels in [`Draw::rect`] may differ from the
    /// shadow's once it is drawn.
    pub fn is_lossy(&self) -> bool {
        self.encoding.is_lossy()
    }

    /// The rectangle's pixels as raw BGRX, in bytes.
    pub fn raw_bytes(&self) -> u64 {
        self.rect.area() * 4
    }

    /// The message body's length in bytes: the image and the drawing
    /// fields around it.
    pub fn encoded_bytes(&self) -> u64 {
        self.body.len() as u64
    }
}

impl std::fmt::Debug for Draw {
    // The body would swamp any log or assertion message.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Draw")
            .field("rect", &self.rect)
            .field("encoding", &self.encoding)
            .field("body_len", &self.body.len())
            .finish()
    }
}

/// What one capture, or one refresh, sends.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Update {
    /// The draws, top first and then left first; empty when nothing
    /// changed. Each draws one rectangle, so their number is the
    /// rectangles sent.
    pub draws: Vec<Draw>,
    /// The pixels the capture held, counting twice any it held twice.
    pub captured_area: u64,
    /// The pixels of the tiles that changed, clipped to the surface.
    pub changed_area: u64,
    /// The tiles that changed; none for a refresh.
    pub changed: Region,
}

impl Update {
    /// Whether there is nothing to send.
    pub fn is_empty(&self) -> bool {
        self.draws.is_empty()
    }

    /// The draws' rectangles as raw BGRX, in bytes.
    pub fn raw_bytes(&self) -> u64 {
        self.draws.iter().map(Draw::raw_bytes).sum()
    }

    /// The draws' message bodies, in bytes.
    pub fn encoded_bytes(&self) -> u64 {
        self.draws.iter().map(Draw::encoded_bytes).sum()
    }
}

/// Turns captures into updates for one display channel's surface: it
/// keeps the shadow, and numbers the images.
pub struct UpdateEncoder {
    shadow: Option<Shadow>,
    next_image_id: u64,
}

impl Default for UpdateEncoder {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for UpdateEncoder {
    // The shadow's pixels would swamp any log or assertion message.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UpdateEncoder")
            .field("shadow", &self.size())
            .field("next_image_id", &self.next_image_id)
            .finish()
    }
}

impl UpdateEncoder {
    /// An encoder with no shadow, whose first image is id 1.
    pub fn new() -> Self {
        Self {
            shadow: None,
            next_image_id: 1,
        }
    }

    /// Drop the shadow, as for a new surface: the next capture must be
    /// complete, and is sent whole. Image ids carry on.
    pub fn reset(&mut self) {
        self.shadow = None;
    }

    /// The size of the surface the shadow holds, if there is one.
    pub fn size(&self) -> Option<Size> {
        self.shadow.as_ref().map(|shadow| shadow.size)
    }

    /// Bring the shadow up to date with `capture`, and encode the draws
    /// that bring the client up to date with it.
    ///
    /// Without a shadow, or with one of another size, `capture` must
    /// include all of the desktop in one patch: it becomes the shadow,
    /// and is sent whole. Otherwise only the tiles that differ are sent,
    /// and an update with no draws means that nothing changed.
    pub fn update(&mut self, capture: &Capture, options: EncodeOptions) -> Result<Update> {
        let captured_area = capture.patches().iter().map(|p| p.rect().area()).sum();
        let changed = match &mut self.shadow {
            Some(shadow) if shadow.size == capture.size() => shadow.apply(capture)?,
            _ => {
                // Free the old shadow before making the new one, and leave
                // none if the capture cannot make one.
                self.shadow = None;
                self.shadow = Some(Shadow::from_capture(capture)?);
                Region::full(capture.size())
            }
        };
        let changed_area = changed.area();
        let draws = self.encode(&changed, options)?;
        Ok(Update {
            draws,
            captured_area,
            changed_area,
            changed,
        })
    }

    /// Encode `region` from the shadow without capturing anything, as
    /// when an area sent lossily is sent again losslessly. The region is
    /// merged and split as an update's changed tiles are. Fails without a
    /// shadow of the region's size.
    pub fn refresh(&mut self, region: &Region, options: EncodeOptions) -> Result<Update> {
        let size = self.size().context("there is no surface to refresh")?;
        ensure!(
            region.size() == size,
            "a region of a {} desktop cannot refresh a {size} surface",
            region.size()
        );
        Ok(Update {
            draws: self.encode(region, options)?,
            captured_area: 0,
            changed_area: 0,
            changed: Region::empty(size),
        })
    }

    /// The draws for `region` of the shadow: merged, split and encoded.
    fn encode(&mut self, region: &Region, options: EncodeOptions) -> Result<Vec<Draw>> {
        let Self {
            shadow,
            next_image_id,
        } = self;
        let shadow = shadow.as_ref().context("there is no shadow to encode")?;
        let mut draws = Vec::new();
        for rect in region.rectangles(MAX_RECTS_PER_FRAME) {
            for piece in split(rect, MAX_DRAW_BYTES) {
                let image_id = *next_image_id;
                *next_image_id = next_image_id.wrapping_add(1).max(1);
                draws.push(encode_draw(shadow, piece, image_id, options)?);
            }
        }
        Ok(draws)
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use shakenfist_spice_protocol::messages::{DrawCopy, WireType};
    use tokio::time::Instant;

    use super::test_support::*;
    use super::*;
    use crate::transcode::geometry::TILE;

    #[test]
    fn the_first_update_is_complete() {
        let desktop = Desktop::pattern(SIZE);
        let mut encoder = UpdateEncoder::new();
        assert_eq!(encoder.size(), None);
        let update = encoder.update(&desktop.capture_all(), LZ4).unwrap();
        assert_eq!(rects(&update), vec![Rectangle::full(SIZE)]);
        let area = Rectangle::full(SIZE).area();
        assert_eq!((update.captured_area, update.changed_area), (area, area));
        assert_eq!(update.raw_bytes(), area * 4);
        assert_eq!(update.encoded_bytes(), update.draws[0].body.len() as u64);
        assert_eq!(encoder.size(), Some(SIZE));
        let mut client = Client::new(SIZE);
        client.apply_all(&update);
        client.assert_shows(&desktop);
    }

    #[test]
    fn an_unchanged_capture_sends_nothing() {
        let desktop = Desktop::pattern(SIZE);
        let (mut encoder, _) = started(&desktop);
        let update = encoder.update(&desktop.capture_all(), LZ4).unwrap();
        assert!(update.is_empty());
        assert_eq!(update.changed_area, 0);
        assert_eq!(update.captured_area, Rectangle::full(SIZE).area());
        assert_eq!((update.raw_bytes(), update.encoded_bytes()), (0, 0));

        // Damage that changed nothing: a capture of part of the desktop.
        let part = rect(30, 40, 150, 90);
        let update = encoder.update(&desktop.capture(&[part]), LZ4).unwrap();
        assert!(update.is_empty());
        assert_eq!(update.captured_area, part.area());

        // A capture of nothing.
        let update = encoder.update(&desktop.capture(&[]), LZ4).unwrap();
        assert!(update.is_empty());
    }

    #[test]
    fn adjacent_changed_tiles_merge() {
        let mut desktop = Desktop::pattern(SIZE);
        let (mut encoder, mut client) = started(&desktop);
        // Tiles (1, 0), (2, 0), (1, 1) and (2, 1), and (3, 1) beside
        // them, which has another span so does not merge down.
        for (x, y) in [(70, 10), (130, 60), (65, 100), (140, 70), (200, 70)] {
            desktop.flip(x, y);
        }
        let update = encoder.update(&desktop.capture_all(), LZ4).unwrap();
        assert_eq!(
            rects(&update),
            vec![rect(64, 0, 128, 64), rect(64, 64, 164, 64)]
        );
        client.apply_all(&update);
        client.assert_shows(&desktop);
    }

    #[test]
    fn two_distant_changes_are_two_rectangles() {
        let size = size(1024, 768);
        let mut desktop = Desktop::pattern(size);
        let (mut encoder, mut client) = started(&desktop);
        desktop.flip(5, 5);
        desktop.flip(1000, 700);
        let update = encoder.update(&desktop.capture_all(), LZ4).unwrap();
        assert_eq!(
            rects(&update),
            vec![rect(0, 0, 64, 64), rect(960, 640, 64, 64)]
        );
        assert_eq!(update.changed_area, 2 * 64 * 64);
        client.apply_all(&update);
        client.assert_shows(&desktop);
    }

    #[test]
    fn over_the_cap_tiles_collapse_and_still_reproduce_the_desktop() {
        // 16 x 12 tiles. Every other tile of every other tile row is 48
        // tiles, none adjacent, so over the cap.
        let size = size(1024, 768);
        let mut desktop = Desktop::pattern(size);
        let (mut encoder, mut client) = started(&desktop);
        let mut points = Vec::new();
        let mut expected = Region::empty(size);
        for row in (0..12).step_by(2) {
            for col in (0..16).step_by(2) {
                let point = rect(col * TILE + 3, row * TILE + 5, 1, 1);
                desktop.flip(point.x, point.y);
                expected.add(point);
                points.push(point);
            }
        }
        assert_eq!(expected.tile_count(), 48);

        // Captured as the changed pixels alone, so the collapsed spans
        // cover tiles that were neither changed nor captured. A change in
        // one of those, not captured, must not reach the client yet.
        let captured = desktop.clone();
        desktop.flip(64 + 7, 9);
        let update = encoder.update(&desktop.capture(&points), LZ4).unwrap();
        assert_eq!(rects(&update), expected.rectangles(MAX_RECTS_PER_FRAME));
        assert_eq!(update.draws.len(), 6, "one span per changed tile row");
        assert_eq!(update.changed_area, 48 * 64 * 64);
        assert_eq!(update.captured_area, 48);
        client.apply_all(&update);
        client.assert_shows(&captured);

        // A complete capture then finds the one change left.
        let update = encoder.update(&desktop.capture_all(), LZ4).unwrap();
        assert_eq!(rects(&update), vec![rect(64, 0, 64, 64)]);
        client.apply_all(&update);
        client.assert_shows(&desktop);
    }

    #[test]
    fn a_rectangle_over_the_limit_is_split_by_rows() {
        // 16 KiB a row, so 256 rows a piece.
        let size = size(4096, 600);
        let desktop = Desktop::pattern(size);
        let mut encoder = UpdateEncoder::new();
        let update = encoder.update(&desktop.capture_all(), RAW).unwrap();
        assert_eq!(
            rects(&update),
            vec![
                rect(0, 0, 4096, 256),
                rect(0, 256, 4096, 256),
                rect(0, 512, 4096, 88),
            ]
        );
        for draw in &update.draws {
            assert!(draw.raw_bytes() <= MAX_DRAW_BYTES as u64);
            assert_eq!(draw.encoding, Encoding::Bitmap);
        }
        assert_eq!(update.raw_bytes(), Rectangle::full(size).area() * 4);
        let mut client = Client::new(size);
        client.apply_all(&update);
        client.assert_shows(&desktop);
    }

    #[test]
    fn any_sequence_of_captures_reproduces_the_desktop() {
        let mut rng = Rng(0x0123_4567_89AB_CDEF);
        let mut desktop = Desktop::pattern(SIZE);
        let (mut encoder, mut client) = started(&desktop);
        let colours = [[0, 0, 0, 0], [255, 255, 255, 0], [10, 200, 30, 0]];
        for step in 0..60 {
            let mut painted = Vec::new();
            for _ in 0..=rng.below(3) {
                let x = rng.below(SIZE.width);
                let y = rng.below(SIZE.height);
                let area = rect(x, y, 1 + rng.below(90), 1 + rng.below(70));
                desktop.fill(area, colours[rng.below(3) as usize]);
                painted.push(area);
            }
            // Capture everything, exactly what was painted, or what was
            // painted rounded out to tiles, as damage would be.
            let capture = match rng.below(3) {
                0 => desktop.capture_all(),
                1 => desktop.capture(&painted),
                _ => {
                    let mut region = Region::empty(SIZE);
                    for &area in &painted {
                        region.add(area);
                    }
                    desktop.capture(&region.rectangles(usize::MAX))
                }
            };
            let options = if rng.below(2) == 0 { LZ4 } else { RAW };
            let update = encoder.update(&capture, options).unwrap();
            assert!(update.draws.len() <= MAX_RECTS_PER_FRAME);
            assert!(update.draws.iter().all(|draw| !draw.is_lossy()));
            client.apply_all(&update);
            client.assert_shows(&desktop);
            assert!(
                encoder.update(&capture, options).unwrap().is_empty(),
                "step {step}: the same capture again changes nothing"
            );
        }
    }

    #[test]
    fn a_new_size_drops_the_shadow() {
        let desktop = Desktop::pattern(SIZE);
        let (mut encoder, _) = started(&desktop);

        let larger = Desktop::pattern(size(300, 200));
        let update = encoder.update(&larger.capture_all(), LZ4).unwrap();
        assert_eq!(rects(&update), vec![rect(0, 0, 300, 200)]);
        assert_eq!(encoder.size(), Some(larger.size));
        let mut client = Client::new(larger.size);
        client.apply_all(&update);
        client.assert_shows(&larger);

        // A capture of another size must be complete.
        let smaller = Desktop::pattern(size(100, 100));
        let part = smaller.capture(&[rect(0, 0, 10, 10)]);
        assert!(encoder.update(&part, LZ4).is_err());
        assert_eq!(encoder.size(), None, "the old shadow is gone");
        let update = encoder.update(&smaller.capture_all(), LZ4).unwrap();
        assert_eq!(rects(&update), vec![rect(0, 0, 100, 100)]);
    }

    #[test]
    fn reset_sends_the_next_capture_whole() {
        let desktop = Desktop::pattern(SIZE);
        let (mut encoder, _) = started(&desktop);
        encoder.reset();
        assert_eq!(encoder.size(), None);
        let part = desktop.capture(&[rect(0, 0, 1, 1)]);
        assert!(encoder.update(&part, LZ4).is_err());
        let update = encoder.update(&desktop.capture_all(), LZ4).unwrap();
        assert_eq!(rects(&update), vec![Rectangle::full(SIZE)]);
    }

    #[test]
    fn a_refresh_makes_a_jpeg_exact() {
        let desktop = Desktop::photo(size(256, 192));
        let mut encoder = UpdateEncoder::new();
        let mut client = Client::new(desktop.size);
        let update = encoder.update(&desktop.capture_all(), AUTO).unwrap();
        assert!(update.draws.iter().all(Draw::is_lossy));
        client.apply_all(&update);
        assert!(client.worst_difference(&desktop) > 0);

        let start = Instant::now();
        let delay = Duration::from_millis(500);
        let mut lossy = LossyTiles::new(delay);
        lossy.reset(desktop.size);
        lossy.record(&update.draws, start);
        assert_eq!(lossy.region(), Region::full(desktop.size));
        assert_eq!(lossy.next_due(), Some(start + delay));

        let due = lossy.due(start + delay);
        let update = encoder.refresh(&due, AUTO.lossless()).unwrap();
        assert!(update.draws.iter().all(|draw| !draw.is_lossy()));
        client.apply_all(&update);
        client.assert_shows(&desktop);
        lossy.clear(&due);
        assert!(lossy.is_empty());
    }

    /// The image id of each draw.
    fn image_ids(update: &Update) -> Vec<u64> {
        update
            .draws
            .iter()
            .map(|draw| {
                DrawCopy::decode(&draw.body)
                    .unwrap()
                    .src_bitmap
                    .unwrap()
                    .descriptor
                    .image_id
            })
            .collect()
    }

    #[test]
    fn image_ids_count_from_one_across_updates_and_resets() {
        let mut desktop = Desktop::pattern(size(1024, 768));
        let mut encoder = UpdateEncoder::new();
        let update = encoder.update(&desktop.capture_all(), LZ4).unwrap();
        assert_eq!(image_ids(&update), vec![1]);
        desktop.flip(5, 5);
        desktop.flip(1000, 700);
        let update = encoder.update(&desktop.capture_all(), LZ4).unwrap();
        assert_eq!(image_ids(&update), vec![2, 3]);
        encoder.reset();
        let update = encoder.update(&desktop.capture_all(), LZ4).unwrap();
        assert_eq!(image_ids(&update), vec![4]);
    }

    #[test]
    fn refresh_sends_the_shadow_again() {
        let desktop = Desktop::pattern(SIZE);
        assert!(UpdateEncoder::new()
            .refresh(&Region::full(SIZE), LZ4)
            .is_err());

        let (mut encoder, mut client) = started(&desktop);
        let mut region = Region::empty(SIZE);
        region.add(rect(70, 70, 100, 10));
        let update = encoder.refresh(&region, RAW).unwrap();
        assert_eq!(rects(&update), vec![rect(64, 64, 128, 64)]);
        assert_eq!((update.captured_area, update.changed_area), (0, 0));
        assert_eq!(update.draws[0].encoding, Encoding::Bitmap);
        client.apply_all(&update);
        client.assert_shows(&desktop);

        let other = Region::full(size(10, 10));
        assert!(encoder.refresh(&other, LZ4).is_err());
    }
}
