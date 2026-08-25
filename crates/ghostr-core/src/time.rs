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

use chrono::{DateTime, FixedOffset, NaiveDate, Utc};
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
        Self { utc_millis, offset_seconds }
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
    #[must_use]
    pub fn to_utc(&self) -> DateTime<Utc> {
        todo!("convert utc_millis to a DateTime<Utc>")
    }

    /// As a datetime in the offset it was observed at.
    #[must_use]
    pub fn to_local(&self) -> DateTime<FixedOffset> {
        todo!("apply offset_seconds to the UTC instant")
    }

    /// The calendar date this instant falls on in `tz`.
    ///
    /// Used to decide which sealing window a memory belongs to. The zone is
    /// supplied by the caller rather than taken from `offset_seconds` because
    /// sealing happens in the identity's *home* zone, not wherever the user was
    /// standing (SPEC Q11).
    #[must_use]
    pub fn date_in(&self, tz: &Tz) -> NaiveDate {
        todo!("project this instant into `tz` and take its calendar date")
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
