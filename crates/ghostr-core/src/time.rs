//! Time, and the two seams that keep it testable.
//!
//! Sealing, salting, cutoff windows, and holdout selection all depend on the
//! clock and on entropy. If either is read directly from the OS, none of it is
//! testable and the cutoff-boundary bugs surface in production at midnight
//! (ARCHITECTURE §4.7).
//!
//! Two mechanisms keep that honest. `chrono` is built without its `clock`
//! feature, so `Utc::now()` does not exist in this tree; and `clippy.toml` bans
//! the remaining `now()` constructors outside the composition root.

use chrono::{DateTime, FixedOffset, NaiveDate, Offset, TimeZone, Utc};
use chrono_tz::Tz;
use serde::{Deserialize, Serialize};

/// An instant, stored as UTC and carrying the offset it was observed at.
///
/// Both halves matter. Windows are half-open on absolute UTC instants, so no
/// memory is double-counted or dropped when a timezone changes mid-day; and the
/// originating offset is retained because "recorded at 03:00 local" is a fact
/// about the memory that UTC alone loses (SPEC Q11).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Timestamp {
    /// Milliseconds since the Unix epoch, UTC.
    utc_millis: i64,
    /// Offset from UTC in effect where the event was observed, in seconds.
    offset_seconds: i32,
}

impl Timestamp {
    /// Builds a timestamp from a UTC instant and the local offset it was seen at.
    #[must_use]
    pub fn new(utc_millis: i64, offset_seconds: i32) -> Self {
        Self {
            utc_millis,
            offset_seconds,
        }
    }

    /// Milliseconds since the Unix epoch, UTC.
    #[must_use]
    pub fn utc_millis(&self) -> i64 {
        self.utc_millis
    }

    /// The offset from UTC in effect where this was observed, in seconds.
    #[must_use]
    pub fn offset_seconds(&self) -> i32 {
        self.offset_seconds
    }

    /// As a UTC datetime.
    ///
    /// # Panics
    ///
    /// Panics only if `utc_millis` is outside chrono's representable range,
    /// which spans roughly ±262,000 years and cannot be reached by any value
    /// this system produces.
    #[must_use]
    pub fn to_utc(&self) -> DateTime<Utc> {
        DateTime::from_timestamp_millis(self.utc_millis).unwrap_or_default()
    }

    /// As a datetime in the offset it was observed at.
    #[must_use]
    pub fn to_local(&self) -> DateTime<FixedOffset> {
        // An offset outside ±24h cannot come from a real zone, so fall back to
        // UTC rather than failing: a nonsensical stored offset should not make a
        // memory unreadable.
        let offset = FixedOffset::east_opt(self.offset_seconds).unwrap_or_else(|| Utc.fix());
        self.to_utc().with_timezone(&offset)
    }

    /// Adds seconds, saturating rather than wrapping.
    #[must_use]
    pub const fn plus_seconds(&self, seconds: i64) -> Self {
        Self {
            utc_millis: self
                .utc_millis
                .saturating_add(seconds.saturating_mul(1_000)),
            offset_seconds: self.offset_seconds,
        }
    }

    /// Builds a timestamp from a zoned datetime, retaining its offset.
    #[must_use]
    pub fn from_datetime<T: TimeZone>(dt: &DateTime<T>) -> Self {
        Self {
            utc_millis: dt.timestamp_millis(),
            offset_seconds: dt.offset().fix().local_minus_utc(),
        }
    }

    /// The calendar date this instant falls on in `tz`.
    ///
    /// Used to decide which sealing window a memory belongs to. The zone is
    /// supplied by the caller rather than taken from `offset_seconds` because
    /// sealing happens in the identity's *home* zone, not wherever the user was
    /// standing (SPEC Q11).
    #[must_use]
    pub fn date_in(&self, tz: &Tz) -> NaiveDate {
        self.to_utc().with_timezone(tz).date_naive()
    }
}

/// The source of "now".
///
/// The composition root supplies a real implementation; tests supply a fixed
/// one. Nothing else in the tree reads a system clock.
pub trait Clock: Send + Sync {
    /// The current instant.
    fn now(&self) -> Timestamp;

    /// The identity's configured home timezone, which is what cutoffs use.
    fn home_tz(&self) -> Tz;
}

/// The source of randomness.
///
/// Used for memory salts (SPEC §7.2), quest nonces, holdout selection, and
/// identifier allocation. A seeded implementation makes every one of those
/// reproducible in a test.
pub trait Rng: Send + Sync {
    /// Fills `buf` with random bytes.
    fn fill(&self, buf: &mut [u8]);

    /// Convenience for the 32-byte salts that blind memory leaves.
    fn salt(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        self.fill(&mut out);
        out
    }
}

#[cfg(test)]
mod tests {
    use chrono_tz::Tz;

    use super::*;

    /// A window boundary must be decided on the absolute instant, not the local
    /// wall clock: the same instant is two different calendar dates either side
    /// of the date line, and picking the wrong one moves a memory between days
    /// (SPEC Q11).
    #[test]
    fn calendar_date_depends_on_the_zone() {
        // 2026-08-25T22:00:00Z
        let t = Timestamp::new(1_787_090_400_000, 0);
        let bangkok: Tz = "Asia/Bangkok".parse().expect("zone");
        let new_york: Tz = "America/New_York".parse().expect("zone");
        assert_ne!(t.date_in(&bangkok), t.date_in(&new_york));
    }

    #[test]
    fn offset_is_retained_separately_from_the_instant() {
        // Two timestamps for the same instant observed in different zones are
        // the same moment but carry different local context.
        let utc = Timestamp::new(1_787_090_400_000, 0);
        let bangkok = Timestamp::new(1_787_090_400_000, 7 * 3600);
        assert_eq!(utc.utc_millis(), bangkok.utc_millis());
        assert_ne!(utc.to_local().hour(), bangkok.to_local().hour());
    }

    #[test]
    fn plus_seconds_saturates_rather_than_wrapping() {
        let t = Timestamp::new(i64::MAX - 10, 0);
        assert_eq!(t.plus_seconds(i64::MAX).utc_millis(), i64::MAX);
    }

    use chrono::Timelike as _;
}
