//! Geometry and captured pixels: sizes, rectangles, tile regions, and the
//! BGRX frames, patches and captures the update pipeline compares and
//! encodes.
//!
//! Copied from andris (https://github.com/shakenfist/andris) at commit
//! e29929fa88bbafebdd1046138112c1a4cfecd2cf: `Size`, `Frame`, `Patch` and
//! `Capture` from `andris/src/platform/mod.rs`, and `TILE`, `Rectangle` and
//! `Region` from `andris/src/platform/damage.rs`, with their tests. Changed
//! from the original:
//!
//! - the rest of andris's platform layer (the desktop seams, `DamageHub`,
//!   `DamageSubscription`, `Gone`) is not copied: here a capture is made
//!   from ryll's surface mirror (`super::capture`), not from a desktop;
//! - let-chains are rewritten as nested `if let`s and `+ use<>` is dropped,
//!   because this crate is edition 2021, not 2024;
//! - doc links to the parts not copied are reworded.
//!
//! Keep the code otherwise as andris has it, so that the copy can be diffed
//! against andris and either brought up to date or replaced by a shared
//! crate. Items andris uses and this crate does not are kept for the same
//! reason, hence the `dead_code` allowance.

#![allow(dead_code)]

use anyhow::{bail, ensure, Context, Result};
use shakenfist_spice_compression::{MAX_IMAGE_DIMENSION, MAX_IMAGE_PIXELS};

/// The size of a desktop or frame, in pixels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Size {
    pub width: u32,
    pub height: u32,
}

impl Size {
    /// Fails unless both sides are at least 1 and at most
    /// `MAX_IMAGE_DIMENSION`, and the pixel count is at most
    /// `MAX_IMAGE_PIXELS`: the limits ryll's encoders and decoders
    /// apply.
    pub fn check(&self) -> Result<()> {
        ensure!(
            self.width > 0 && self.height > 0,
            "a {self} desktop has no pixels"
        );
        ensure!(
            self.width <= MAX_IMAGE_DIMENSION && self.height <= MAX_IMAGE_DIMENSION,
            "a {self} desktop has a side over {MAX_IMAGE_DIMENSION} pixels"
        );
        ensure!(
            self.width as usize * self.height as usize <= MAX_IMAGE_PIXELS,
            "a {self} desktop has more than {MAX_IMAGE_PIXELS} pixels"
        );
        Ok(())
    }
}

impl std::fmt::Display for Size {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}x{}", self.width, self.height)
    }
}

/// A BGRX image, of the whole desktop or one rectangle of it: 32 bits a
/// pixel, bytes B, G, R and an unused byte, rows `stride` bytes apart.
///
/// The fields are private, so a `Frame` always satisfies what
/// [`Frame::new`] checks.
#[derive(Clone, PartialEq, Eq)]
pub struct Frame {
    size: Size,
    stride: usize,
    data: Vec<u8>,
}

impl Frame {
    /// Wrap `data` as a `width` x `height` BGRX frame whose rows start
    /// `stride` bytes apart.
    ///
    /// Fails if the size is refused by [`Size::check`], if `stride` is
    /// less than `width * 4`, or if `data` is too short to hold the last
    /// row. The last row needs only `width * 4` bytes, so a buffer with
    /// no trailing padding is accepted.
    pub fn new(width: u32, height: u32, stride: usize, data: Vec<u8>) -> Result<Self> {
        let size = Size { width, height };
        size.check()?;
        let row_bytes = width as usize * 4;
        ensure!(
            stride >= row_bytes,
            "a {size} frame needs a stride of at least {row_bytes} bytes, not {stride}"
        );
        let Some(needed) = stride
            .checked_mul(height as usize - 1)
            .and_then(|n| n.checked_add(row_bytes))
        else {
            bail!("a {size} frame with a stride of {stride} bytes is too large to address");
        };
        ensure!(
            data.len() >= needed,
            "a {size} frame with a stride of {stride} bytes needs {needed} bytes of data, not {}",
            data.len()
        );
        Ok(Self { size, stride, data })
    }

    pub fn width(&self) -> u32 {
        self.size.width
    }

    pub fn height(&self) -> u32 {
        self.size.height
    }

    pub fn size(&self) -> Size {
        self.size
    }

    /// Bytes from the start of one row to the start of the next.
    pub fn stride(&self) -> usize {
        self.stride
    }

    /// The pixel buffer, including any row padding.
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Row `y` without its padding, `width * 4` bytes; `None` past the
    /// last row.
    pub fn row(&self, y: u32) -> Option<&[u8]> {
        self.band(y, 1)
    }

    /// The bytes of `count` rows starting at row `top`, including the
    /// padding between them but not after the last: a buffer of that
    /// many rows with this frame's width and stride. `None` if `count`
    /// is zero or the rows run past the bottom of the frame.
    pub fn band(&self, top: u32, count: u32) -> Option<&[u8]> {
        if count == 0 || top.checked_add(count)? > self.size.height {
            return None;
        }
        // Frame::new bounded the whole buffer, so these cannot overflow.
        let start = top as usize * self.stride;
        let end = (top + count - 1) as usize * self.stride + self.size.width as usize * 4;
        self.data.get(start..end)
    }

    /// A copy of the pixels of `rect`, with no row padding. Fails unless
    /// `rect` has pixels and lies within the frame.
    pub fn crop(&self, rect: Rectangle) -> Result<Frame> {
        ensure!(
            rect.lies_within(self.size),
            "{rect} does not lie within a {} frame",
            self.size
        );
        let row_bytes = rect.width as usize * 4;
        let left = rect.x as usize * 4;
        let mut data = Vec::with_capacity(row_bytes * rect.height as usize);
        for y in rect.y..rect.y + rect.height {
            let row = self
                .row(y)
                .with_context(|| format!("row {y} lies outside a {} frame", self.size))?;
            data.extend_from_slice(&row[left..left + row_bytes]);
        }
        Frame::new(rect.width, rect.height, row_bytes, data)
    }
}

impl std::fmt::Debug for Frame {
    // The pixels would swamp any log or assertion message.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Frame")
            .field("size", &self.size)
            .field("stride", &self.stride)
            .field("data_len", &self.data.len())
            .finish()
    }
}

/// The pixels of one rectangle of the desktop.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Patch {
    rect: Rectangle,
    pixels: Frame,
}

impl Patch {
    /// `pixels` as the contents of `rect`. Fails unless they are the
    /// rectangle's size.
    pub fn new(rect: Rectangle, pixels: Frame) -> Result<Self> {
        ensure!(
            pixels.size() == rect.size(),
            "a {} image cannot be the pixels of {rect}",
            pixels.size()
        );
        Ok(Self { rect, pixels })
    }

    /// Where on the desktop the pixels belong.
    pub fn rect(&self) -> Rectangle {
        self.rect
    }

    /// The pixels, exactly the rectangle's size.
    pub fn pixels(&self) -> &Frame {
        &self.pixels
    }

    /// The pixels, consuming the patch.
    pub fn into_pixels(self) -> Frame {
        self.pixels
    }
}

/// What a capture read: the desktop's size when it was read, and the
/// pixels of each rectangle asked for, clipped to that size.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Capture {
    size: Size,
    patches: Vec<Patch>,
}

impl Capture {
    /// `patches` of a desktop of `size`. Fails unless every patch lies
    /// within it.
    pub fn new(size: Size, patches: Vec<Patch>) -> Result<Self> {
        for patch in &patches {
            ensure!(
                patch.rect.lies_within(size),
                "{} does not lie within a {size} desktop",
                patch.rect
            );
        }
        Ok(Self { size, patches })
    }

    /// One patch of all of `frame`, as a capture of the whole
    /// surface is.
    pub fn whole(frame: Frame) -> Result<Self> {
        let size = frame.size();
        Self::new(size, vec![Patch::new(Rectangle::full(size), frame)?])
    }

    /// The parts of `frame`, a capture of the whole desktop, that `rects`
    /// cover, each clipped to it. A rectangle wholly outside it yields no
    /// patch.
    pub fn cut(frame: &Frame, rects: &[Rectangle]) -> Result<Self> {
        let size = frame.size();
        let patches = rects
            .iter()
            .filter_map(|rect| rect.clip(size))
            .map(|rect| Patch::new(rect, frame.crop(rect)?))
            .collect::<Result<_>>()?;
        Self::new(size, patches)
    }

    /// The desktop's size when it was captured.
    pub fn size(&self) -> Size {
        self.size
    }

    /// The patches, in the order their rectangles were asked for.
    pub fn patches(&self) -> &[Patch] {
        &self.patches
    }

    /// The patches, consuming the capture.
    pub fn into_patches(self) -> Vec<Patch> {
        self.patches
    }

    /// The whole desktop as one frame. Fails unless the capture is one
    /// patch covering all of it, as a capture of the whole
    /// surface is.
    pub fn into_whole(self) -> Result<Frame> {
        let full = Rectangle::full(self.size);
        match <[Patch; 1]>::try_from(self.patches) {
            Ok([patch]) if patch.rect == full => Ok(patch.pixels),
            Ok([patch]) => bail!(
                "a capture of {} is not all of a {} desktop",
                patch.rect,
                self.size
            ),
            Err(patches) => bail!(
                "a capture of {} patches is not one of the whole desktop",
                patches.len()
            ),
        }
    }
}

/// The side of a tile, in pixels: the granularity of a [`Region`].
pub const TILE: u32 = 64;

/// An area of the desktop: `width` x `height` pixels whose top left
/// pixel is (`x`, `y`). A rectangle with a zero side is empty.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Rectangle {
    pub x: u32,
    pub y: u32,
    pub width: u32,
    pub height: u32,
}

impl Rectangle {
    /// The rectangle `width` x `height` at (`x`, `y`).
    pub const fn new(x: u32, y: u32, width: u32, height: u32) -> Self {
        Self {
            x,
            y,
            width,
            height,
        }
    }

    /// The whole of a desktop of `size`.
    pub const fn full(size: Size) -> Self {
        Self::new(0, 0, size.width, size.height)
    }

    /// Whether the rectangle has no pixels.
    pub const fn is_empty(&self) -> bool {
        self.width == 0 || self.height == 0
    }

    /// One past the rightmost column. A `u64`, so it cannot overflow.
    pub const fn right(&self) -> u64 {
        self.x as u64 + self.width as u64
    }

    /// One past the bottom row. A `u64`, so it cannot overflow.
    pub const fn bottom(&self) -> u64 {
        self.y as u64 + self.height as u64
    }

    /// The number of pixels.
    pub const fn area(&self) -> u64 {
        self.width as u64 * self.height as u64
    }

    /// The rectangle's own size, ignoring its position.
    pub const fn size(&self) -> Size {
        Size {
            width: self.width,
            height: self.height,
        }
    }

    /// Whether the rectangle has pixels and lies wholly within a desktop
    /// of `size`.
    pub fn lies_within(&self, size: Size) -> bool {
        !self.is_empty()
            && self.right() <= u64::from(size.width)
            && self.bottom() <= u64::from(size.height)
    }

    /// The part of the rectangle within a desktop of `size`, or `None`
    /// if no pixel of it is.
    pub fn clip(&self, size: Size) -> Option<Rectangle> {
        let right = self.right().min(u64::from(size.width));
        let bottom = self.bottom().min(u64::from(size.height));
        let (x, y) = (u64::from(self.x), u64::from(self.y));
        if right <= x || bottom <= y {
            return None;
        }
        // Each difference is at most a side of `size`, so fits a u32.
        Some(Rectangle::new(
            self.x,
            self.y,
            (right - x) as u32,
            (bottom - y) as u32,
        ))
    }

    /// Whether the two rectangles share a pixel.
    pub fn intersects(&self, other: &Rectangle) -> bool {
        !self.is_empty()
            && !other.is_empty()
            && u64::from(self.x) < other.right()
            && u64::from(other.x) < self.right()
            && u64::from(self.y) < other.bottom()
            && u64::from(other.y) < self.bottom()
    }

    /// The column and row of each [`TILE`] x [`TILE`] tile the rectangle
    /// touches, counted from the desktop's origin, top first and then
    /// left first. An empty rectangle touches none. Nothing is clipped:
    /// a rectangle reaching past a desktop touches tiles outside its
    /// grid.
    pub fn tiles(&self) -> impl Iterator<Item = (u32, u32)> {
        let tile = u64::from(TILE);
        let (cols, rows) = if self.is_empty() {
            (0..0, 0..0)
        } else {
            // A right or bottom edge is below 2^33, so its tile index is
            // below 2^27 and fits a u32.
            (
                self.x / TILE..self.right().div_ceil(tile) as u32,
                self.y / TILE..self.bottom().div_ceil(tile) as u32,
            )
        };
        rows.flat_map(move |row| cols.clone().map(move |col| (col, row)))
    }

    /// The part of the rectangle within tile (`col`, `row`), or `None`
    /// if it does not touch that tile.
    pub fn tile_part(&self, col: u32, row: u32) -> Option<Rectangle> {
        let tile = u64::from(TILE);
        let left = (u64::from(col) * tile).max(u64::from(self.x));
        let top = (u64::from(row) * tile).max(u64::from(self.y));
        let right = ((u64::from(col) + 1) * tile).min(self.right());
        let bottom = ((u64::from(row) + 1) * tile).min(self.bottom());
        if right <= left || bottom <= top {
            return None;
        }
        // The part lies within the rectangle, so each of these fits a u32.
        Some(Rectangle::new(
            left as u32,
            top as u32,
            (right - left) as u32,
            (bottom - top) as u32,
        ))
    }

    /// Whether `other` lies wholly within this rectangle. An empty
    /// `other` lies within any rectangle.
    pub fn contains(&self, other: &Rectangle) -> bool {
        other.is_empty()
            || (other.x >= self.x
                && other.y >= self.y
                && other.right() <= self.right()
                && other.bottom() <= self.bottom())
    }
}

impl std::fmt::Display for Rectangle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}x{}+{}+{}", self.width, self.height, self.x, self.y)
    }
}

/// A set of [`TILE`] x [`TILE`] tiles of a desktop of one size. The
/// tiles of the last column and row may be partial; every rectangle a
/// region yields is clipped to the desktop.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Region {
    size: Size,
    columns: u32,
    rows: u32,
    /// One bit a tile, row by row: tile (`col`, `row`) is bit
    /// `row * columns + col`.
    bits: Vec<u64>,
}

impl Region {
    /// No tiles of a desktop of `size`.
    pub fn empty(size: Size) -> Self {
        let columns = size.width.div_ceil(TILE);
        let rows = size.height.div_ceil(TILE);
        let tiles = columns as usize * rows as usize;
        Self {
            size,
            columns,
            rows,
            bits: vec![0; tiles.div_ceil(64)],
        }
    }

    /// Every tile of a desktop of `size`.
    pub fn full(size: Size) -> Self {
        let mut region = Self::empty(size);
        region.add(Rectangle::full(size));
        region
    }

    /// The size of the desktop the region belongs to.
    pub fn size(&self) -> Size {
        self.size
    }

    /// Tiles across and down a desktop of this size.
    pub fn grid(&self) -> (u32, u32) {
        (self.columns, self.rows)
    }

    /// Add every tile `rect` touches, after clipping it to the desktop.
    /// A rectangle wholly outside the desktop adds nothing.
    pub fn add(&mut self, rect: Rectangle) {
        let Some(rect) = rect.clip(self.size) else {
            return;
        };
        // Clipped, so every tile it touches is within the grid.
        for (col, row) in rect.tiles() {
            self.insert_tile(col, row);
        }
    }

    /// Add every tile of `other`. If `other` belongs to a desktop of
    /// another size, its rectangles are clipped to this region's desktop
    /// and rounded out to its tiles.
    pub fn union(&mut self, other: &Region) {
        if other.size == self.size {
            for (mine, theirs) in self.bits.iter_mut().zip(&other.bits) {
                *mine |= theirs;
            }
        } else {
            for rect in other.rectangles(usize::MAX) {
                self.add(rect);
            }
        }
    }

    /// Whether the region has no tiles.
    pub fn is_empty(&self) -> bool {
        self.bits.iter().all(|&word| word == 0)
    }

    /// How many tiles the region holds.
    pub fn tile_count(&self) -> usize {
        self.bits
            .iter()
            .map(|word| word.count_ones() as usize)
            .sum()
    }

    /// The pixels of the region's tiles, clipped to its desktop.
    pub fn area(&self) -> u64 {
        self.tiles()
            .map(|(col, row)| self.tile_rect(col, row).area())
            .sum()
    }

    /// Whether tile (`col`, `row`) is in the region; `false` outside the
    /// grid.
    pub fn contains_tile(&self, col: u32, row: u32) -> bool {
        let Some(bit) = self.bit(col, row) else {
            return false;
        };
        self.bits
            .get(bit / 64)
            .is_some_and(|word| word & (1 << (bit % 64)) != 0)
    }

    /// Add tile (`col`, `row`). A tile outside the grid adds nothing.
    pub fn insert_tile(&mut self, col: u32, row: u32) {
        if let Some(bit) = self.bit(col, row) {
            if let Some(word) = self.bits.get_mut(bit / 64) {
                *word |= 1 << (bit % 64);
            }
        }
    }

    /// Remove tile (`col`, `row`). A tile outside the grid removes
    /// nothing.
    pub fn remove_tile(&mut self, col: u32, row: u32) {
        if let Some(bit) = self.bit(col, row) {
            if let Some(word) = self.bits.get_mut(bit / 64) {
                *word &= !(1 << (bit % 64));
            }
        }
    }

    /// The column and row of each of the region's tiles, top first and
    /// then left first. Skips empty stretches a word of 64 tiles at a
    /// time, and allocates nothing.
    pub fn tiles(&self) -> impl Iterator<Item = (u32, u32)> + '_ {
        let columns = self.columns.max(1) as usize;
        self.bits.iter().enumerate().flat_map(move |(at, &word)| {
            let mut word = word;
            std::iter::from_fn(move || {
                if word == 0 {
                    return None;
                }
                let index = at * 64 + word.trailing_zeros() as usize;
                word &= word - 1;
                // Only bits within the grid are ever set, so both fit
                // a u32.
                Some(((index % columns) as u32, (index / columns) as u32))
            })
        })
    }

    /// The pixels of tile (`col`, `row`), clipped to the desktop: a whole
    /// [`TILE`] x [`TILE`] tile except in the last column and row. A tile
    /// outside the grid is an empty rectangle at the desktop's edge.
    pub fn tile_rect(&self, col: u32, row: u32) -> Rectangle {
        self.span_rect(col, col.saturating_add(1), row, row.saturating_add(1))
    }

    /// The region's tiles as at most `max` disjoint rectangles, clipped
    /// to the desktop, top first and then left first. A `max` of 0 is
    /// taken as 1.
    ///
    /// Tiles are merged in stages, each used only if the one before
    /// yields more than `max` rectangles:
    ///
    /// 1. runs of tiles within a tile row, then runs with the same span
    ///    in adjacent rows (exact);
    /// 2. one span per tile row, from its first tile to its last, merged
    ///    down the same way;
    /// 3. full-width bands of consecutive tile rows;
    /// 4. one rectangle bounding every tile.
    ///
    /// Stages 2 to 4 cover tiles the region does not hold.
    pub fn rectangles(&self, max: usize) -> Vec<Rectangle> {
        let max = max.max(1);
        let exact = self.merge(|row| self.runs(row));
        if exact.len() <= max {
            return exact;
        }
        let spans = self.merge(|row| self.span(row).into_iter().collect());
        if spans.len() <= max {
            return spans;
        }
        let bands = self.merge(|row| {
            self.span(row)
                .map(|_| (0, self.columns))
                .into_iter()
                .collect()
        });
        if bands.len() <= max {
            return bands;
        }
        self.bounds().into_iter().collect()
    }

    /// One rectangle bounding every tile, or `None` if there are none.
    pub fn bounds(&self) -> Option<Rectangle> {
        let mut rows = (0..self.rows).filter_map(|row| self.span(row).map(|span| (row, span)));
        let (top, (mut left, mut right)) = rows.next()?;
        let mut bottom = top;
        for (row, (first, end)) in rows {
            bottom = row;
            left = left.min(first);
            right = right.max(end);
        }
        Some(self.span_rect(left, right, top, bottom + 1))
    }

    /// Tile (`col`, `row`)'s bit, or `None` outside the grid.
    fn bit(&self, col: u32, row: u32) -> Option<usize> {
        (col < self.columns && row < self.rows)
            .then(|| row as usize * self.columns as usize + col as usize)
    }

    /// The runs of consecutive tiles in tile row `row`, as half-open
    /// column ranges, left first.
    fn runs(&self, row: u32) -> Vec<(u32, u32)> {
        let mut runs = Vec::new();
        let mut start = None;
        for col in 0..self.columns {
            match (self.contains_tile(col, row), start) {
                (true, None) => start = Some(col),
                (false, Some(first)) => {
                    runs.push((first, col));
                    start = None;
                }
                _ => {}
            }
        }
        if let Some(first) = start {
            runs.push((first, self.columns));
        }
        runs
    }

    /// The columns from tile row `row`'s first tile to its last, half
    /// open, or `None` if it has none.
    fn span(&self, row: u32) -> Option<(u32, u32)> {
        let first = (0..self.columns).find(|&col| self.contains_tile(col, row))?;
        let last = (0..self.columns)
            .rev()
            .find(|&col| self.contains_tile(col, row))?;
        Some((first, last + 1))
    }

    /// Merge the column ranges `spans` gives for each tile row into
    /// rectangles, extending a rectangle down while the next row has a
    /// range with exactly its columns.
    fn merge(&self, spans: impl Fn(u32) -> Vec<(u32, u32)>) -> Vec<Rectangle> {
        // Each open rectangle: its columns and its first row.
        let mut open: Vec<(u32, u32, u32)> = Vec::new();
        let mut done = Vec::new();
        for row in 0..self.rows {
            let mut next = Vec::new();
            for (first, end) in spans(row) {
                match open.iter().position(|o| o.0 == first && o.1 == end) {
                    Some(at) => next.push(open.swap_remove(at)),
                    None => next.push((first, end, row)),
                }
            }
            done.extend(
                open.drain(..)
                    .map(|(first, end, top)| self.span_rect(first, end, top, row)),
            );
            open = next;
        }
        done.extend(
            open.into_iter()
                .map(|(first, end, top)| self.span_rect(first, end, top, self.rows)),
        );
        done.sort_by_key(|rect| (rect.y, rect.x));
        done
    }

    /// The pixels of tile columns `first..end` and tile rows
    /// `top..bottom`, clipped to the desktop. Columns and rows beyond the
    /// grid clip to an empty rectangle at its edge.
    fn span_rect(&self, first: u32, end: u32, top: u32, bottom: u32) -> Rectangle {
        let tile = u64::from(TILE);
        let (width, height) = (u64::from(self.size.width), u64::from(self.size.height));
        let x = (u64::from(first) * tile).min(width);
        let y = (u64::from(top) * tile).min(height);
        let right = (u64::from(end) * tile).min(width);
        let bottom = (u64::from(bottom) * tile).min(height);
        // Each is at most a side of the desktop, so fits a u32.
        Rectangle::new(
            x as u32,
            y as u32,
            right.saturating_sub(x) as u32,
            bottom.saturating_sub(y) as u32,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 4 x 3 tiles, the last column 36 pixels wide and the last row 8
    /// rows tall.
    const SIZE: Size = Size {
        width: 228,
        height: 136,
    };

    fn rect(x: u32, y: u32, width: u32, height: u32) -> Rectangle {
        Rectangle::new(x, y, width, height)
    }

    /// A region of `SIZE` holding the tiles marked `#` in `rows`.
    fn tiles(rows: &[&str]) -> Region {
        let mut region = Region::empty(SIZE);
        for (row, line) in rows.iter().enumerate() {
            for (col, mark) in line.chars().enumerate() {
                if mark == '#' {
                    region.add(rect(col as u32 * TILE, row as u32 * TILE, 1, 1));
                }
            }
        }
        region
    }

    #[test]
    fn size_limits() {
        assert!(Size {
            width: 1,
            height: 1
        }
        .check()
        .is_ok());
        assert!(Size {
            width: 0,
            height: 768
        }
        .check()
        .is_err());
        assert!(Size {
            width: MAX_IMAGE_DIMENSION + 1,
            height: 1
        }
        .check()
        .is_err());
        assert!(
            Size {
                width: MAX_IMAGE_DIMENSION,
                height: MAX_IMAGE_DIMENSION
            }
            .check()
            .is_err(),
            "the pixel count cap also applies"
        );
    }

    #[test]
    fn frame_accepts_padded_and_unpadded_buffers() {
        assert!(Frame::new(4, 2, 16, vec![0; 32]).is_ok());
        // The last row needs no padding.
        assert!(Frame::new(4, 2, 20, vec![0; 36]).is_ok());
    }

    #[test]
    fn frame_refuses_bad_geometry() {
        assert!(Frame::new(0, 2, 16, vec![0; 32]).is_err());
        assert!(Frame::new(4, 2, 15, vec![0; 32]).is_err(), "short stride");
        assert!(Frame::new(4, 2, 20, vec![0; 35]).is_err(), "short data");
    }

    #[test]
    fn frame_rows_and_bands() {
        // Three rows of two pixels, stride 12 (4 bytes of padding).
        let data: Vec<u8> = (0..36).collect();
        let frame = Frame::new(2, 3, 12, data).unwrap();
        assert_eq!(frame.row(0).unwrap(), &(0..8).collect::<Vec<u8>>()[..]);
        assert_eq!(frame.row(2).unwrap(), &(24..32).collect::<Vec<u8>>()[..]);
        assert!(frame.row(3).is_none());
        assert_eq!(
            frame.band(1, 2).unwrap(),
            &(12..32).collect::<Vec<u8>>()[..]
        );
        assert!(frame.band(0, 0).is_none());
        assert!(frame.band(2, 2).is_none());
        assert!(frame.band(u32::MAX, 2).is_none());
    }

    #[test]
    fn crop_copies_a_rectangle_without_padding() {
        // Three rows of two pixels, stride 12 (4 bytes of padding).
        let data: Vec<u8> = (0..36).collect();
        let frame = Frame::new(2, 3, 12, data).unwrap();
        let cropped = frame.crop(Rectangle::new(1, 1, 1, 2)).unwrap();
        assert_eq!(
            cropped.size(),
            Size {
                width: 1,
                height: 2
            }
        );
        assert_eq!(cropped.stride(), 4);
        assert_eq!(cropped.data(), &[16, 17, 18, 19, 28, 29, 30, 31]);
        assert_eq!(
            frame.crop(Rectangle::full(frame.size())).unwrap().row(2),
            frame.row(2)
        );
        assert!(frame.crop(Rectangle::new(1, 1, 2, 1)).is_err());
        assert!(frame.crop(Rectangle::new(0, 0, 0, 1)).is_err());
    }

    #[test]
    fn patch_and_capture_checks() {
        let frame = Frame::new(2, 2, 8, vec![0; 16]).unwrap();
        assert!(Patch::new(Rectangle::new(5, 5, 2, 2), frame.clone()).is_ok());
        assert!(Patch::new(Rectangle::new(0, 0, 2, 1), frame.clone()).is_err());
        let patch = Patch::new(Rectangle::new(5, 5, 2, 2), frame.clone()).unwrap();
        let small = Size {
            width: 6,
            height: 7,
        };
        assert!(Capture::new(small, vec![patch.clone()]).is_err());
        let size = Size {
            width: 7,
            height: 7,
        };
        let capture = Capture::new(size, vec![patch]).unwrap();
        assert!(capture.into_whole().is_err(), "a part is not the whole");
        assert!(Capture::new(size, vec![]).unwrap().into_whole().is_err());
        assert_eq!(
            Capture::whole(frame.clone()).unwrap().into_whole().unwrap(),
            frame
        );
    }

    #[test]
    fn cut_clips_and_drops_rectangles() {
        let data: Vec<u8> = (0..64).collect();
        let frame = Frame::new(4, 4, 16, data).unwrap();
        let capture = Capture::cut(
            &frame,
            &[
                Rectangle::new(2, 2, 10, 10),
                Rectangle::new(9, 9, 1, 1),
                Rectangle::new(0, 0, 1, 1),
            ],
        )
        .unwrap();
        assert_eq!(capture.size(), frame.size());
        let rects: Vec<Rectangle> = capture.patches().iter().map(Patch::rect).collect();
        assert_eq!(
            rects,
            vec![Rectangle::new(2, 2, 2, 2), Rectangle::new(0, 0, 1, 1)]
        );
        assert_eq!(
            capture.patches()[0].pixels().data(),
            &[40, 41, 42, 43, 44, 45, 46, 47, 56, 57, 58, 59, 60, 61, 62, 63]
        );
    }

    #[test]
    fn rectangle_clip_and_intersect() {
        let size = Size {
            width: 100,
            height: 50,
        };
        assert_eq!(rect(90, 40, 20, 20).clip(size), Some(rect(90, 40, 10, 10)));
        assert_eq!(rect(100, 0, 5, 5).clip(size), None);
        assert_eq!(rect(0, 0, 0, 5).clip(size), None);
        assert_eq!(
            rect(u32::MAX, u32::MAX, u32::MAX, u32::MAX).clip(size),
            None
        );
        assert_eq!(
            Rectangle::full(size).clip(size),
            Some(Rectangle::full(size))
        );
        assert!(rect(0, 0, 10, 10).intersects(&rect(9, 9, 1, 1)));
        assert!(!rect(0, 0, 10, 10).intersects(&rect(10, 0, 1, 1)));
        assert!(!rect(0, 0, 10, 10).intersects(&rect(5, 5, 0, 1)));
        assert!(rect(90, 40, 10, 10).lies_within(size));
        assert!(!rect(90, 40, 11, 10).lies_within(size));
        assert!(!rect(0, 0, 0, 10).lies_within(size));
    }

    #[test]
    fn add_rounds_out_to_tiles() {
        let mut region = Region::empty(SIZE);
        assert!(region.is_empty());
        region.add(rect(63, 63, 2, 2));
        assert_eq!(region.tile_count(), 4);
        for (col, row) in [(0, 0), (1, 0), (0, 1), (1, 1)] {
            assert!(region.contains_tile(col, row));
        }
        assert!(!region.contains_tile(2, 0));
        assert!(!region.contains_tile(99, 99));
    }

    #[test]
    fn add_clips_rectangles_partly_or_wholly_outside() {
        let mut region = Region::empty(SIZE);
        region.add(rect(200, 130, 1000, 1000));
        assert_eq!(region.tile_count(), 1);
        assert!(region.contains_tile(3, 2));

        let mut region = Region::empty(SIZE);
        region.add(rect(SIZE.width, 0, 10, 10));
        region.add(rect(0, SIZE.height, 10, 10));
        region.add(rect(u32::MAX, u32::MAX, u32::MAX, u32::MAX));
        region.add(rect(0, 0, 0, 0));
        assert!(region.is_empty());
    }

    #[test]
    fn full_covers_every_tile_and_clips_the_last_column_and_row() {
        let region = Region::full(SIZE);
        assert_eq!(region.grid(), (4, 3));
        assert_eq!(region.tile_count(), 12);
        assert_eq!(region.rectangles(32), vec![Rectangle::full(SIZE)]);
        assert_eq!(region.bounds(), Some(Rectangle::full(SIZE)));
    }

    #[test]
    fn the_largest_desktop_fits() {
        let size = Size {
            width: MAX_IMAGE_DIMENSION,
            height: MAX_IMAGE_DIMENSION,
        };
        let region = Region::full(size);
        assert_eq!(region.grid(), (256, 256));
        assert_eq!(region.bits.len(), 1024, "one bit a tile");
        assert_eq!(region.tile_count(), 65536);
        assert_eq!(region.rectangles(1), vec![Rectangle::full(size)]);
        let mut corner = Region::empty(size);
        corner.add(rect(MAX_IMAGE_DIMENSION - 1, MAX_IMAGE_DIMENSION - 1, 1, 1));
        assert_eq!(corner.rectangles(1), vec![rect(16320, 16320, 64, 64)]);
    }

    #[test]
    fn a_zero_sized_region_is_empty() {
        let region = Region::full(Size {
            width: 0,
            height: 0,
        });
        assert!(region.is_empty());
        assert!(region.rectangles(32).is_empty());
        assert_eq!(region.bounds(), None);
    }

    #[test]
    fn rectangles_of_an_empty_region() {
        assert!(Region::empty(SIZE).rectangles(32).is_empty());
    }

    #[test]
    fn rectangles_merge_runs_within_a_row() {
        let region = tiles(&["##.#", "....", "...."]);
        assert_eq!(
            region.rectangles(32),
            vec![rect(0, 0, 128, 64), rect(192, 0, 36, 64)]
        );
    }

    #[test]
    fn rectangles_merge_equal_spans_down() {
        let region = tiles(&[".##.", ".##.", "...."]);
        assert_eq!(region.rectangles(32), vec![rect(64, 0, 128, 128)]);
    }

    #[test]
    fn rectangles_do_not_merge_unequal_spans() {
        let region = tiles(&[".##.", ".###", ".##."]);
        assert_eq!(
            region.rectangles(32),
            vec![
                rect(64, 0, 128, 64),
                rect(64, 64, 164, 64),
                rect(64, 128, 128, 8),
            ]
        );
    }

    #[test]
    fn rectangles_merge_a_span_that_reappears_beside_another() {
        // The left column runs down all three rows while the right
        // breaks and restarts.
        let region = tiles(&["#..#", "#...", "#..#"]);
        assert_eq!(
            region.rectangles(32),
            vec![
                rect(0, 0, 64, 136),
                rect(192, 0, 36, 64),
                rect(192, 128, 36, 8),
            ]
        );
    }

    #[test]
    fn rectangles_clip_the_last_column_and_row() {
        let region = tiles(&["....", "....", "...#"]);
        assert_eq!(region.rectangles(32), vec![rect(192, 128, 36, 8)]);
    }

    #[test]
    fn over_the_cap_rows_collapse_to_spans() {
        let region = tiles(&["#.#.", "#.#.", "...."]);
        assert_eq!(region.rectangles(2).len(), 2);
        assert_eq!(region.rectangles(1), vec![rect(0, 0, 192, 128)]);
        // Spans merge down only while they are equal.
        let region = tiles(&["#.#.", ".#.#", "#.#."]);
        assert_eq!(region.rectangles(6).len(), 6, "exact");
        assert_eq!(
            region.rectangles(3),
            vec![
                rect(0, 0, 192, 64),
                rect(64, 64, 164, 64),
                rect(0, 128, 192, 8),
            ]
        );
    }

    #[test]
    fn over_the_cap_spans_collapse_to_bands() {
        // Three single tiles whose spans differ, so stage 2 still yields
        // three rectangles.
        let region = tiles(&["#...", ".#..", "#..."]);
        assert_eq!(region.rectangles(3).len(), 3);
        // With a cap of 2 the rows become full-width bands, which merge
        // into one.
        assert_eq!(region.rectangles(2), vec![rect(0, 0, 228, 136)]);
    }

    #[test]
    fn over_the_cap_bands_collapse_to_the_bounds() {
        // Two separate bands even when full width.
        let region = tiles(&[".#..", "....", "..#."]);
        assert_eq!(region.rectangles(2).len(), 2, "two single tiles");
        assert_eq!(
            region.rectangles(1),
            vec![rect(64, 0, 128, 136)],
            "the bounds, not full width"
        );
    }

    #[test]
    fn a_cap_of_zero_is_one() {
        let region = tiles(&["#..#", "....", "...."]);
        assert_eq!(region.rectangles(0).len(), 1);
    }

    #[test]
    fn union_of_the_same_size_adds_tiles() {
        let mut region = tiles(&["#...", "....", "...."]);
        region.union(&tiles(&["....", "....", "...#"]));
        assert_eq!(region, tiles(&["#...", "....", "...#"]));
    }

    #[test]
    fn union_of_another_size_clips() {
        let mut region = Region::empty(SIZE);
        let mut larger = Region::empty(Size {
            width: 1000,
            height: 1000,
        });
        // Inside; straddling the right edge; wholly outside.
        larger.add(rect(100, 100, 1, 1));
        larger.add(rect(200, 100, 1, 1));
        larger.add(rect(900, 900, 1, 1));
        region.union(&larger);
        assert_eq!(region, tiles(&["....", ".#.#", "...."]));

        let mut region = Region::empty(SIZE);
        let smaller = Region::full(Size {
            width: 10,
            height: 10,
        });
        region.union(&smaller);
        assert_eq!(region, tiles(&["#...", "....", "...."]));
    }

    #[test]
    fn a_rectangle_lists_the_tiles_it_touches() {
        assert_eq!(
            rect(63, 10, 2, 60).tiles().collect::<Vec<_>>(),
            vec![(0, 0), (1, 0), (0, 1), (1, 1)]
        );
        assert_eq!(
            rect(64, 64, 64, 64).tiles().collect::<Vec<_>>(),
            vec![(1, 1)]
        );
        // Unaligned, but empty.
        assert_eq!(rect(10, 10, 0, 5).tiles().count(), 0);
        assert_eq!(rect(10, 10, 5, 0).tiles().count(), 0);
        // Nothing overflows at the far edge of the coordinates.
        let far = rect(u32::MAX, u32::MAX, u32::MAX, u32::MAX);
        assert_eq!(far.tiles().next(), Some((u32::MAX / TILE, u32::MAX / TILE)));
    }

    #[test]
    fn a_rectangle_is_cut_into_its_tile_parts() {
        let r = rect(60, 0, 10, 70);
        assert_eq!(r.tile_part(0, 0), Some(rect(60, 0, 4, 64)));
        assert_eq!(r.tile_part(1, 0), Some(rect(64, 0, 6, 64)));
        assert_eq!(r.tile_part(0, 1), Some(rect(60, 64, 4, 6)));
        assert_eq!(r.tile_part(2, 0), None);
        assert_eq!(rect(0, 0, 0, 0).tile_part(0, 0), None);
        let parts: u64 = r
            .tiles()
            .filter_map(|(col, row)| r.tile_part(col, row))
            .map(|part| part.area())
            .sum();
        assert_eq!(parts, r.area());
    }

    #[test]
    fn rectangle_containment() {
        let outer = rect(10, 10, 20, 20);
        assert!(outer.contains(&outer));
        assert!(outer.contains(&rect(15, 15, 15, 15)));
        assert!(!outer.contains(&rect(15, 15, 16, 15)));
        assert!(!outer.contains(&rect(9, 15, 2, 2)));
        assert!(outer.contains(&rect(500, 500, 0, 0)), "empty");
    }

    #[test]
    fn tiles_lists_the_region_top_first_then_left() {
        let region = tiles(&["#..#", ".#..", "...#"]);
        assert_eq!(
            region.tiles().collect::<Vec<_>>(),
            vec![(0, 0), (3, 0), (1, 1), (3, 2)]
        );
        assert_eq!(Region::empty(SIZE).tiles().count(), 0);
        // Across the word boundaries of the largest desktop.
        let size = Size {
            width: MAX_IMAGE_DIMENSION,
            height: MAX_IMAGE_DIMENSION,
        };
        let full = Region::full(size);
        assert_eq!(full.tiles().count(), 65536);
        assert_eq!(full.tiles().last(), Some((255, 255)));
    }

    #[test]
    fn tile_rect_clips_to_the_desktop() {
        let region = Region::empty(SIZE);
        assert_eq!(region.tile_rect(0, 0), rect(0, 0, 64, 64));
        assert_eq!(region.tile_rect(3, 1), rect(192, 64, 36, 64));
        assert_eq!(region.tile_rect(3, 2), rect(192, 128, 36, 8));
        assert!(region.tile_rect(4, 0).is_empty(), "outside the grid");
        assert!(region.tile_rect(u32::MAX, u32::MAX).is_empty());
    }

    #[test]
    fn tiles_are_inserted_and_removed_one_at_a_time() {
        let mut region = Region::empty(SIZE);
        region.insert_tile(3, 2);
        region.insert_tile(1, 0);
        // Outside the grid: not taken as a tile of the next row.
        region.insert_tile(4, 0);
        assert_eq!(region, tiles(&[".#..", "....", "...#"]));
        assert_eq!(region.area(), 64 * 64 + 36 * 8);
        region.remove_tile(1, 0);
        region.remove_tile(4, 0);
        assert_eq!(region, tiles(&["....", "....", "...#"]));
        assert_eq!(Region::full(SIZE).area(), Rectangle::full(SIZE).area());
    }
}
