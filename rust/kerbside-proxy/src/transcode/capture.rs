//! The update pipeline's input: captures read from ryll's surface mirror.
//!
//! The pipeline copied from andris (`super::updates`) takes a [`Capture`]:
//! BGRX patches of the parts of a desktop that may have changed. Here the
//! desktop is the backend's primary surface as ryll's renderer has drawn
//! it, a [`DisplaySurface`] holding RGBA, and what may have changed is the
//! [`DamageRegion`] its draws recorded since the last
//! [`DisplaySurface::take_damage`].
//!
//! The damage says only where to look. Ryll's region is coarse (it merges
//! rectangles and collapses to their bounds past 32), and a draw may write
//! the pixels that were already there, so the pipeline's shadow comparison
//! decides what is actually sent, as it does for andris's X11 damage.
//!
//! Only the damaged rectangles are converted, so the cost of a capture
//! follows the damage, not the surface. The unused fourth byte of each BGRX
//! pixel is always 0, whatever alpha the surface holds, so that alpha never
//! reads as a change and the pipeline's encoders see what `FMT_32_XRGB`
//! means.

use anyhow::{Context, Result};
use shakenfist_spice_renderer::{DamageRect, DamageRegion, DisplaySurface};

use super::geometry::{Capture, Frame, Patch, Rectangle, Region, Size};

/// The size of `surface`, as the pipeline takes it.
pub fn surface_size(surface: &DisplaySurface) -> Size {
    Size {
        width: surface.width,
        height: surface.height,
    }
}

/// A ryll damage rectangle (exclusive right and bottom edges) as a
/// pipeline rectangle. An empty one, or one whose edges are reversed, is
/// empty.
pub fn rectangle(rect: &DamageRect) -> Rectangle {
    Rectangle::new(rect.left, rect.top, rect.width(), rect.height())
}

/// The tiles of a `size` surface that `damage` touches, for postponing the
/// lossless refresh of lossy tiles that are still changing.
pub fn damage_region(size: Size, damage: &DamageRegion) -> Region {
    let mut region = Region::empty(size);
    for rect in damage.rects() {
        region.add(rectangle(rect));
    }
    region
}

/// A capture of all of `surface`, in one patch.
pub fn whole(surface: &DisplaySurface) -> Result<Capture> {
    let size = surface_size(surface);
    size.check()?;
    Capture::new(size, vec![patch(surface, Rectangle::full(size))?])
}

/// A capture of the parts of `surface` that `damage` covers, each clipped
/// to the surface. Damage wholly outside the surface yields no patch.
pub fn damaged(surface: &DisplaySurface, damage: &DamageRegion) -> Result<Capture> {
    let size = surface_size(surface);
    size.check()?;
    let patches = damage
        .rects()
        .iter()
        .filter_map(|rect| rectangle(rect).clip(size))
        .map(|rect| patch(surface, rect))
        .collect::<Result<_>>()?;
    Capture::new(size, patches)
}

/// `rect` of `surface`, which must lie within it, as a BGRX patch.
fn patch(surface: &DisplaySurface, rect: Rectangle) -> Result<Patch> {
    let row_bytes = surface.width as usize * 4;
    let pixels = surface.pixels();
    let mut data = Vec::with_capacity(rect.area() as usize * 4);
    for y in rect.y..rect.y + rect.height {
        let start = y as usize * row_bytes + rect.x as usize * 4;
        let row = pixels
            .get(start..start + rect.width as usize * 4)
            .with_context(|| format!("{rect} lies outside a {} surface", surface_size(surface)))?;
        rgba_to_bgrx(row, &mut data);
    }
    let frame = Frame::new(rect.width, rect.height, rect.width as usize * 4, data)?;
    Patch::new(rect, frame)
}

/// Append the RGBA pixels of `rgba` to `out` as BGRX, with the unused byte
/// 0. A trailing partial pixel is ignored.
pub fn rgba_to_bgrx(rgba: &[u8], out: &mut Vec<u8>) {
    for [r, g, b, _alpha] in rgba.as_chunks::<4>().0 {
        out.extend_from_slice(&[*b, *g, *r, 0]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transcode::geometry::TILE;
    use crate::transcode::updates::test_support::{Client, Desktop, LZ4};
    use crate::transcode::updates::UpdateEncoder;

    #[test]
    fn rgba_becomes_bgrx_with_the_unused_byte_cleared() {
        // Every channel distinct, and alpha neither 0 nor 255, so that a
        // swapped pair of channels, or alpha carried through, shows.
        let mut out = Vec::new();
        rgba_to_bgrx(&[0x11, 0x22, 0x33, 0x44, 0xA1, 0xB2, 0xC3, 0x7F], &mut out);
        assert_eq!(out, vec![0x33, 0x22, 0x11, 0x00, 0xC3, 0xB2, 0xA1, 0x00]);
        // A partial pixel is not converted.
        rgba_to_bgrx(&[1, 2, 3], &mut out);
        assert_eq!(out.len(), 8);
    }

    #[test]
    fn damage_rectangles_have_exclusive_edges() {
        assert_eq!(
            rectangle(&DamageRect::new(10, 20, 30, 25)),
            Rectangle::new(10, 20, 20, 5)
        );
        assert!(rectangle(&DamageRect::new(30, 20, 10, 25)).is_empty());
        let size = Size {
            width: 200,
            height: 100,
        };
        let mut damage = DamageRegion::new();
        damage.add(DamageRect::new(60, 0, 70, 10));
        let region = damage_region(size, &damage);
        assert_eq!(region.tile_count(), 2, "touches tiles (0, 0) and (1, 0)");
        assert!(region.contains_tile(0, 0) && region.contains_tile(1, 0));
    }

    /// A surface of `width` x `height` painted with a pattern in which every
    /// channel and the alpha vary.
    fn painted(width: u32, height: u32) -> DisplaySurface {
        let mut surface = DisplaySurface::new(0, width, height);
        let mut pixels = Vec::new();
        for y in 0..height {
            for x in 0..width {
                pixels.extend_from_slice(&[
                    (x * 7) as u8,
                    (y * 5) as u8,
                    (x + y) as u8,
                    (x * y) as u8,
                ]);
            }
        }
        surface.blit(0, 0, width, height, &pixels);
        surface
    }

    /// What the pipeline should see of `surface`: its pixels as BGRX.
    fn desktop_of(surface: &DisplaySurface) -> Desktop {
        let mut pixels = Vec::new();
        rgba_to_bgrx(surface.pixels(), &mut pixels);
        Desktop {
            size: surface_size(surface),
            pixels,
        }
    }

    #[test]
    fn a_whole_capture_is_the_surface_as_bgrx() {
        let surface = painted(100, 70);
        let capture = whole(&surface).unwrap();
        assert_eq!(capture.patches().len(), 1);
        let patch = &capture.patches()[0];
        assert_eq!(patch.rect(), Rectangle::full(surface_size(&surface)));
        // Pixel (3, 2): RGBA (21, 10, 5, 6) becomes BGRX (5, 10, 21, 0).
        let row = patch.pixels().row(2).unwrap();
        assert_eq!(&row[12..16], &[5, 10, 21, 0]);
        assert_eq!(desktop_of(&surface).pixels, patch.pixels().data());
    }

    #[test]
    fn damaged_captures_only_the_damage_clipped_to_the_surface() {
        let surface = painted(100, 70);
        let mut damage = DamageRegion::new();
        damage.add(DamageRect::new(5, 6, 15, 9));
        damage.add(DamageRect::new(90, 60, 500, 500));
        damage.add(DamageRect::new(300, 300, 400, 400));
        let capture = damaged(&surface, &damage).unwrap();
        let rects: Vec<Rectangle> = capture.patches().iter().map(Patch::rect).collect();
        assert_eq!(
            rects,
            vec![Rectangle::new(5, 6, 10, 3), Rectangle::new(90, 60, 10, 10)]
        );
        // The first patch's top left pixel is the surface's (5, 6).
        let first = capture.patches()[0].pixels().row(0).unwrap();
        assert_eq!(&first[..4], &[11, 30, 35, 0]);
    }

    #[test]
    fn surface_damage_drives_the_pipeline_to_the_surface_s_pixels() {
        let mut surface = painted(228, 136);
        let mut encoder = UpdateEncoder::new();
        let mut client = Client::new(surface_size(&surface));

        // A new surface is all damage, and its first update is all of it.
        let damage = surface.take_damage();
        assert!(!damage.is_empty());
        let update = encoder.update(&whole(&surface).unwrap(), LZ4).unwrap();
        client.apply_all(&update);
        client.assert_shows(&desktop_of(&surface));

        // A draw of one pixel sends its tile alone.
        surface.blit(70, 70, 1, 1, &[1, 2, 3, 4]);
        let damage = surface.take_damage();
        let update = encoder
            .update(&damaged(&surface, &damage).unwrap(), LZ4)
            .unwrap();
        let rects: Vec<Rectangle> = update.draws.iter().map(|d| d.rect).collect();
        assert_eq!(rects, vec![Rectangle::new(TILE, TILE, TILE, TILE)]);
        client.apply_all(&update);
        client.assert_shows(&desktop_of(&surface));

        // A draw that writes what was already there is damage, but sends
        // nothing; nor does a change of alpha alone.
        let same = surface.pixels()[..4].to_vec();
        surface.blit(0, 0, 1, 1, &same);
        let mut alpha_only = same.clone();
        alpha_only[3] ^= 0xFF;
        surface.blit(0, 0, 1, 1, &alpha_only);
        let damage = surface.take_damage();
        assert!(!damage.is_empty());
        let update = encoder
            .update(&damaged(&surface, &damage).unwrap(), LZ4)
            .unwrap();
        assert!(update.is_empty());
    }
}
