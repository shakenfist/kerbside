//! Where the client holds only an approximation of the shadow, because
//! it was last sent lossily, and when each such tile is due to be sent
//! again losslessly.
//!
//! Copied from andris (https://github.com/shakenfist/andris) at commit
//! e29929fa88bbafebdd1046138112c1a4cfecd2cf, `andris/src/server/updates/lossy.rs`.
//! Changed from the original:
//!
//! - `LossyTiles::mark` and `LossyTiles::make_due`, which only video
//!   streams use, and their test, are not copied;
//! - let-chains are rewritten as nested `if let`s, because this crate is
//!   edition 2021, not 2024;
//! - paths into andris's platform layer point at `crate::transcode::geometry`.
//!
//! Keep it otherwise as andris has it, so that the copy can be diffed
//! against andris and either brought up to date or replaced by a shared
//! crate (see `crate::transcode`).

use std::time::Duration;

use tokio::time::Instant;

use super::Draw;
use crate::transcode::geometry::{Region, Size};

/// The tiles of a surface whose pixels the client may hold only
/// approximately, because they were last sent lossily, each with the time
/// it is due to be sent again losslessly.
///
/// A tile becomes lossy when a lossy draw touches it, due `delay` later.
/// Damage that touches a lossy tile postpones it to `delay` after the
/// damage. A tile lying wholly within a lossless draw, or in a region a
/// refresh sent, is exact again. Each tile keeps its own time, so an area
/// that keeps changing does not hold back the refresh of one that has
/// stopped.
///
/// The display channel asks for [`LossyTiles::next_due`] every time it
/// wakes, which includes every message from the client, so the earliest
/// time is kept up to date by the methods that change the times, and
/// reading it costs nothing.
#[derive(Debug, Clone)]
pub struct LossyTiles {
    delay: Duration,
    /// The lossy tiles. A tile is in it exactly when its entry in `due`
    /// is set.
    lossy: Region,
    /// One entry a tile, row by row: when it is due, or `None` if it is
    /// exact.
    due: Vec<Option<Instant>>,
    /// The earliest entry of `due`, or `None` if every tile is exact.
    next_due: Option<Instant>,
}

impl LossyTiles {
    /// No lossy tiles, and no surface until [`LossyTiles::reset`] gives
    /// one; a tile is refreshed once it has been still for `delay`.
    pub fn new(delay: Duration) -> Self {
        Self {
            delay,
            lossy: Region::empty(Size {
                width: 0,
                height: 0,
            }),
            due: Vec::new(),
            next_due: None,
        }
    }

    /// Forget every lossy tile, for a new surface of `size`.
    pub fn reset(&mut self, size: Size) {
        self.lossy = Region::empty(size);
        let (columns, rows) = self.lossy.grid();
        self.due = vec![None; columns as usize * rows as usize];
        self.next_due = None;
    }

    /// The size of the surface the tiles belong to.
    pub fn size(&self) -> Size {
        self.lossy.size()
    }

    /// Whether every tile is exact.
    pub fn is_empty(&self) -> bool {
        self.next_due.is_none()
    }

    /// The lossy tiles, as a region.
    pub fn region(&self) -> Region {
        self.lossy.clone()
    }

    /// When the earliest lossy tile is due, if there is one.
    pub fn next_due(&self) -> Option<Instant> {
        self.next_due
    }

    /// The lossy tiles due by `now`, as a region. They stay lossy until
    /// [`LossyTiles::clear`].
    pub fn due(&self, now: Instant) -> Region {
        let mut region = Region::empty(self.size());
        if self.next_due.is_some_and(|next| next <= now) {
            for (col, row) in self.lossy.tiles() {
                if self.get(col, row).is_some_and(|due| due <= now) {
                    region.insert_tile(col, row);
                }
            }
        }
        region
    }

    /// Postpone every lossy tile `damage` touches to `delay` after `now`.
    /// Damage of a desktop of another size touches nothing: the surface is
    /// about to be replaced.
    pub fn touch(&mut self, damage: &Region, now: Instant) {
        if damage.size() != self.size() || self.is_empty() {
            return;
        }
        let later = now + self.delay;
        let columns = self.lossy.grid().0;
        for (col, row) in self.lossy.tiles() {
            if damage.contains_tile(col, row) {
                if let Some(due) = self.due.get_mut(index(columns, col, row)) {
                    *due = Some(later);
                }
            }
        }
        self.find_next_due();
    }

    /// Record what `draws`, sent at `now`, did to the client: each tile a
    /// lossless draw covers wholly is exact, and then each tile a lossy
    /// draw touches is lossy, due `delay` after `now`.
    pub fn record(&mut self, draws: &[Draw], now: Instant) {
        if draws.is_empty() {
            return;
        }
        if !self.is_empty() {
            for draw in draws.iter().filter(|draw| !draw.is_lossy()) {
                for (col, row) in draw.rect.tiles() {
                    if draw.rect.contains(&self.lossy.tile_rect(col, row)) {
                        self.set(col, row, None);
                    }
                }
            }
        }
        let later = now + self.delay;
        for draw in draws.iter().filter(|draw| draw.is_lossy()) {
            for (col, row) in draw.rect.tiles() {
                self.set(col, row, Some(later));
            }
        }
        self.find_next_due();
    }

    /// Mark every tile of `region` exact, as once a refresh has sent it
    /// losslessly. A region of another size clears nothing.
    pub fn clear(&mut self, region: &Region) {
        if region.size() != self.size() || self.is_empty() {
            return;
        }
        for (col, row) in region.tiles() {
            self.set(col, row, None);
        }
        self.find_next_due();
    }

    /// When tile (`col`, `row`) is due, or `None` if it is exact or
    /// outside the grid.
    fn get(&self, col: u32, row: u32) -> Option<Instant> {
        let (columns, rows) = self.lossy.grid();
        if col >= columns || row >= rows {
            return None;
        }
        self.due.get(index(columns, col, row)).copied().flatten()
    }

    /// Make tile (`col`, `row`) due at `due`, or exact if `None`. A tile
    /// outside the grid is left alone. Leaves `next_due` stale; the
    /// caller brings it up to date with [`LossyTiles::find_next_due`].
    fn set(&mut self, col: u32, row: u32, due: Option<Instant>) {
        let (columns, rows) = self.lossy.grid();
        if col >= columns || row >= rows {
            return;
        }
        if let Some(slot) = self.due.get_mut(index(columns, col, row)) {
            *slot = due;
            match due {
                Some(_) => self.lossy.insert_tile(col, row),
                None => self.lossy.remove_tile(col, row),
            }
        }
    }

    /// Bring `next_due` up to date after the times changed: a scan of
    /// the lossy tiles alone, made only when they change.
    fn find_next_due(&mut self) {
        let columns = self.lossy.grid().0;
        let due = &self.due;
        self.next_due = self
            .lossy
            .tiles()
            .filter_map(|(col, row)| due.get(index(columns, col, row)).copied().flatten())
            .min();
    }
}

/// The entry of tile (`col`, `row`) in a grid `columns` tiles wide.
fn index(columns: u32, col: u32, row: u32) -> usize {
    row as usize * columns as usize + col as usize
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::transcode::geometry::Rectangle;
    use crate::transcode::updates::test_support::*;
    use crate::transcode::updates::Encoding;

    /// A draw of `rect` encoded as `encoding`, with no body.
    fn draw(rect: Rectangle, encoding: Encoding) -> Draw {
        Draw {
            rect,
            encoding,
            body: Vec::new(),
        }
    }

    fn region(size: Size, rects: &[Rectangle]) -> Region {
        let mut region = Region::empty(size);
        for &r in rects {
            region.add(r);
        }
        region
    }

    #[test]
    fn lossy_tiles_fall_due_after_the_delay() {
        let delay = Duration::from_millis(500);
        let start = Instant::now();
        let mut lossy = LossyTiles::new(delay);
        assert!(lossy.is_empty());
        assert_eq!(lossy.next_due(), None);
        lossy.reset(SIZE);
        assert_eq!(lossy.size(), SIZE);

        // A lossy draw across four tiles, partly.
        lossy.record(&[draw(rect(60, 60, 10, 10), Encoding::Jpeg)], start);
        let four = region(SIZE, &[rect(0, 0, 128, 128)]);
        assert_eq!(lossy.region(), four);
        assert_eq!(lossy.next_due(), Some(start + delay));
        assert!(lossy
            .due(start + delay - Duration::from_millis(1))
            .is_empty());
        assert_eq!(lossy.due(start + delay), four);

        // Damage on one of them postpones it alone.
        let later = start + Duration::from_millis(300);
        lossy.touch(&region(SIZE, &[rect(70, 70, 1, 1)]), later);
        assert_eq!(
            lossy.due(start + delay),
            region(SIZE, &[rect(0, 0, 128, 64), rect(0, 64, 64, 64)])
        );
        assert_eq!(lossy.due(later + delay), four);
        // Damage elsewhere touches nothing; so does damage of another size.
        lossy.touch(&region(SIZE, &[rect(200, 100, 1, 1)]), later);
        lossy.touch(&Region::full(size(64, 64)), later + delay);
        assert_eq!(lossy.region(), four);
        assert_eq!(lossy.next_due(), Some(start + delay));

        lossy.clear(&region(SIZE, &[rect(0, 0, 1, 1)]));
        assert_eq!(lossy.region().tile_count(), 3);
        lossy.reset(SIZE);
        assert!(lossy.is_empty());
    }

    #[test]
    fn lossless_draws_clear_only_the_tiles_they_cover() {
        let start = Instant::now();
        let mut lossy = LossyTiles::new(Duration::from_millis(500));
        lossy.reset(SIZE);
        lossy.record(&[draw(Rectangle::full(SIZE), Encoding::Jpeg)], start);
        assert_eq!(lossy.region(), Region::full(SIZE));

        // Tile (1, 0) wholly, and tile (2, 0) in part; the clipped tile
        // (3, 2) wholly, though it is 36 x 8.
        lossy.record(
            &[
                draw(rect(64, 0, 100, 64), Encoding::Lz4),
                draw(rect(192, 128, 36, 8), Encoding::Bitmap),
            ],
            start,
        );
        assert!(!lossy.region().contains_tile(1, 0));
        assert!(lossy.region().contains_tile(2, 0));
        assert!(!lossy.region().contains_tile(3, 2));
        assert_eq!(lossy.region().tile_count(), 10);

        // A frame with lossless and lossy draws on one tile leaves it
        // lossy; a lossy draw re-dates the tiles it touches.
        let later = start + Duration::from_millis(100);
        lossy.record(
            &[
                draw(rect(64, 0, 64, 64), Encoding::Jpeg),
                draw(rect(64, 0, 64, 64), Encoding::Lz4),
            ],
            later,
        );
        assert!(lossy.region().contains_tile(1, 0));
        assert_eq!(
            lossy.due(start + Duration::from_millis(500)).tile_count(),
            10
        );
    }

    #[test]
    fn next_due_follows_record_touch_and_clear() {
        let delay = Duration::from_millis(500);
        let start = Instant::now();
        let ms = |n: u64| start + Duration::from_millis(n);
        let mut lossy = LossyTiles::new(delay);
        lossy.reset(SIZE);
        let a = rect(0, 0, 64, 64);
        let b = rect(128, 64, 64, 64);

        lossy.record(&[draw(a, Encoding::Jpeg)], ms(0));
        lossy.record(&[draw(b, Encoding::Jpeg)], ms(100));
        assert_eq!(lossy.next_due(), Some(ms(500)));
        // Damage on the earlier tile makes the other the earliest.
        lossy.touch(&region(SIZE, &[a]), ms(200));
        assert_eq!(lossy.next_due(), Some(ms(600)));
        // A lossless draw over the other leaves the first.
        lossy.record(&[draw(b, Encoding::Lz4)], ms(250));
        assert_eq!(lossy.next_due(), Some(ms(700)));
        lossy.clear(&region(SIZE, &[a]));
        assert_eq!(lossy.next_due(), None);
        assert!(lossy.is_empty());
        assert!(lossy.due(ms(10_000)).is_empty());
    }

    #[test]
    fn next_due_is_always_the_earliest_tile() {
        let delay = Duration::from_millis(50);
        let start = Instant::now();
        let mut rng = Rng(0x10_55_7E_57_10_55_7E_57);
        let mut lossy = LossyTiles::new(delay);
        lossy.reset(SIZE);
        for step in 0..200u64 {
            let now = start + Duration::from_millis(step);
            let r = rect(
                rng.below(SIZE.width),
                rng.below(SIZE.height),
                1 + rng.below(100),
                1 + rng.below(100),
            );
            match rng.below(4) {
                0 | 1 => {
                    let encoding = if rng.below(2) == 0 {
                        Encoding::Jpeg
                    } else {
                        Encoding::Lz4
                    };
                    lossy.record(&[draw(r, encoding)], now);
                }
                2 => lossy.touch(&region(SIZE, &[r]), now),
                _ => lossy.clear(&region(SIZE, &[r])),
            }
            let slow = lossy
                .region()
                .tiles()
                .filter_map(|(col, row)| lossy.get(col, row))
                .min();
            assert_eq!(lossy.next_due(), slow, "step {step}");
            assert_eq!(lossy.is_empty(), lossy.region().is_empty());
        }
    }
}
