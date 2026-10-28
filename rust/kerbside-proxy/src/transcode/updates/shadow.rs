//! The shadow: the pixels of the client's surface as andris last sent
//! them, which each capture is compared with a tile at a time. The
//! [parent module](super) describes how it fits the update pipeline.
//!
//! Copied from andris (https://github.com/shakenfist/andris) at commit
//! e29929fa88bbafebdd1046138112c1a4cfecd2cf, `andris/src/server/updates/shadow.rs`.
//! Changed from the original:
//!
//! - `Shadow::compare`, which only andris's scrub uses, is not copied;
//! - paths into andris's platform layer point at `crate::transcode::geometry`.
//!
//! Keep it otherwise as andris has it, so that the copy can be diffed
//! against andris and either brought up to date or replaced by a shared
//! crate (see `crate::transcode`).

use anyhow::{ensure, Context, Result};
use shakenfist_spice_compression::Bgrx;

use crate::transcode::geometry::{Capture, Patch, Rectangle, Region, Size};

/// The pixels the client's surface holds: BGRX, rows `width * 4` bytes
/// apart with no padding.
pub(super) struct Shadow {
    pub(super) size: Size,
    pixels: Vec<u8>,
}

impl Shadow {
    /// A shadow of `capture`, one of whose patches must cover the whole
    /// desktop. Every patch is copied in, in order.
    pub(super) fn from_capture(capture: &Capture) -> Result<Self> {
        let size = capture.size();
        let full = Rectangle::full(size);
        ensure!(
            capture.patches().iter().any(|patch| patch.rect() == full),
            "the first capture of a {size} surface must be all of it"
        );
        let mut shadow = Self {
            size,
            pixels: vec![0; size.width as usize * size.height as usize * 4],
        };
        for patch in capture.patches() {
            shadow.copy_in(patch, patch.rect())?;
        }
        Ok(shadow)
    }

    fn row_bytes(&self) -> usize {
        self.size.width as usize * 4
    }

    /// Where in the buffer the `width` pixels from (`x`, `y`) are.
    fn span(&self, x: u32, y: u32, width: u32) -> std::ops::Range<usize> {
        let start = y as usize * self.row_bytes() + x as usize * 4;
        start..start + width as usize * 4
    }

    /// The tiles where `capture` differs from the shadow, copying each
    /// part that differs into it.
    pub(super) fn apply(&mut self, capture: &Capture) -> Result<Region> {
        let mut changed = Region::empty(self.size);
        for patch in capture.patches() {
            for part in tile_parts(patch.rect()) {
                if self.differs(patch, part)? {
                    self.copy_in(patch, part)?;
                    changed.add(part);
                }
            }
        }
        Ok(changed)
    }

    /// Whether `part` of `patch` differs from the shadow, compared a row
    /// at a time.
    fn differs(&self, patch: &Patch, part: Rectangle) -> Result<bool> {
        for y in part.y..part.y + part.height {
            let theirs = patch_row(patch, part, y)?;
            let mine = self
                .pixels
                .get(self.span(part.x, y, part.width))
                .with_context(|| format!("{part} lies outside a {} shadow", self.size))?;
            if theirs != mine {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Copy `part` of `patch` into the shadow.
    fn copy_in(&mut self, patch: &Patch, part: Rectangle) -> Result<()> {
        let size = self.size;
        for y in part.y..part.y + part.height {
            let theirs = patch_row(patch, part, y)?;
            let span = self.span(part.x, y, part.width);
            self.pixels
                .get_mut(span)
                .with_context(|| format!("{part} lies outside a {size} shadow"))?
                .copy_from_slice(theirs);
        }
        Ok(())
    }

    /// `rect` of the shadow as an image to encode.
    pub(super) fn image(&self, rect: Rectangle) -> Result<Bgrx<'_>> {
        ensure!(
            rect.lies_within(self.size),
            "{rect} does not lie within a {} surface",
            self.size
        );
        let start = self.span(rect.x, rect.y, rect.width).start;
        let end = self.span(rect.x, rect.y + rect.height - 1, rect.width).end;
        let data = self
            .pixels
            .get(start..end)
            .with_context(|| format!("{rect} lies outside a {} shadow", self.size))?;
        Bgrx::new(data, rect.width, rect.height, self.row_bytes())
            .with_context(|| format!("{rect} of a {} surface is not a valid image", self.size))
    }
}

/// The desktop's row `y` within `part` of `patch`, without padding.
fn patch_row(patch: &Patch, part: Rectangle, y: u32) -> Result<&[u8]> {
    let rect = patch.rect();
    let left = (part.x - rect.x) as usize * 4;
    patch
        .pixels()
        .row(y - rect.y)
        .and_then(|row| row.get(left..left + part.width as usize * 4))
        .with_context(|| format!("{part} lies outside a patch of {rect}"))
}

/// The parts of `rect` within each [`TILE`] x [`TILE`] tile it touches,
/// top first and then left first.
///
/// [`TILE`]: crate::transcode::geometry::TILE
fn tile_parts(rect: Rectangle) -> impl Iterator<Item = Rectangle> {
    rect.tiles()
        .filter_map(move |(col, row)| rect.tile_part(col, row))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transcode::updates::test_support::*;
    use crate::transcode::updates::UpdateEncoder;

    #[test]
    fn tile_parts_cut_a_rectangle_at_tile_edges() {
        assert_eq!(
            tile_parts(rect(60, 30, 70, 40)).collect::<Vec<_>>(),
            vec![
                rect(60, 30, 4, 34),
                rect(64, 30, 64, 34),
                rect(128, 30, 2, 34),
                rect(60, 64, 4, 6),
                rect(64, 64, 64, 6),
                rect(128, 64, 2, 6),
            ]
        );
        assert_eq!(tile_parts(rect(0, 0, 64, 64)).count(), 1);
        assert_eq!(tile_parts(rect(10, 10, 0, 10)).count(), 0);
    }

    #[test]
    fn a_first_capture_that_is_not_complete_is_refused() {
        let desktop = Desktop::pattern(SIZE);
        let mut encoder = UpdateEncoder::new();
        let part = desktop.capture(&[rect(0, 0, 64, 64)]);
        let error = encoder.update(&part, LZ4).unwrap_err();
        assert!(error.to_string().contains("must be all of it"));
        assert_eq!(encoder.size(), None);
        // Complete, though in two patches, one of them whole.
        let capture = desktop.capture(&[rect(0, 0, 10, 10), Rectangle::full(SIZE)]);
        assert_eq!(encoder.update(&capture, LZ4).unwrap().draws.len(), 1);
    }

    #[test]
    fn stride_padding_is_not_compared() {
        let desktop = Desktop::pattern(SIZE);
        let (mut encoder, _) = started(&desktop);
        let capture = desktop.capture_padded(&[Rectangle::full(SIZE)], 0x55);
        assert!(encoder.update(&capture, LZ4).unwrap().is_empty());
    }

    #[test]
    fn a_pixel_change_sends_only_its_tile() {
        let (w, h) = (SIZE.width, SIZE.height);
        let points = [
            (0, 0),
            (w - 1, 0),
            (0, h - 1),
            (w - 1, h - 1),
            (w / 2, 0),
            (w / 2, h - 1),
            (0, h / 2),
            (w - 1, h / 2),
            (w / 2, h / 2),
        ];
        for (x, y) in points {
            let tile = tile_of(SIZE, x, y);
            // Captured whole, as the one pixel, and as its tile.
            for captured in [Rectangle::full(SIZE), rect(x, y, 1, 1), tile] {
                let mut desktop = Desktop::pattern(SIZE);
                let (mut encoder, mut client) = started(&desktop);
                desktop.flip(x, y);
                let update = encoder.update(&desktop.capture(&[captured]), LZ4).unwrap();
                assert_eq!(
                    rects(&update),
                    vec![tile],
                    "a change at ({x}, {y}) captured as {captured}"
                );
                assert_eq!(update.changed_area, tile.area());
                client.apply_all(&update);
                client.assert_shows(&desktop);
            }
        }
    }

    #[test]
    fn a_partial_tile_capture_compares_only_what_it_covers() {
        let mut desktop = Desktop::pattern(SIZE);
        let (mut encoder, mut client) = started(&desktop);
        // A band of rows 30 to 99, which covers part of tile rows 0 and 1.
        // Tile (0, 0) changes within the band and above it; tile (2, 1)
        // changes only below it.
        let mut seen = desktop.clone();
        desktop.flip(10, 50);
        seen.flip(10, 50);
        desktop.flip(10, 10);
        desktop.flip(140, 120);
        let band = rect(0, 30, SIZE.width, 70);
        let update = encoder.update(&desktop.capture(&[band]), LZ4).unwrap();
        assert_eq!(rects(&update), vec![rect(0, 0, 64, 64)]);
        assert_eq!(update.captured_area, band.area());
        // The tile is sent whole, from the shadow, so the part outside the
        // band is what the client already had.
        client.apply_all(&update);
        client.assert_shows(&seen);

        let update = encoder.update(&desktop.capture_all(), LZ4).unwrap();
        assert_eq!(
            rects(&update),
            vec![rect(0, 0, 64, 64), rect(128, 64, 64, 64)]
        );
        client.apply_all(&update);
        client.assert_shows(&desktop);
    }
}
