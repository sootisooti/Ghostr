//! Deciding when a day ends, and which memories belong to it.
//!
//! # Why this is harder than it looks
//!
//! "Seal at 23:59 local" is ambiguous across a timezone change, and a westward
//! flight can produce a thirty-hour day. Ghostr seals on the identity's
//! configured **home** timezone and records the zone actually in effect, so a
//! long or short day is a fact the footage shows rather than a discrepancy it
//! hides (SPEC Q11).
//!
//! Windows are half-open on absolute UTC instants regardless, so no memory is
//! ever double-counted or dropped no matter what the wall clock did.

use chrono::NaiveDate;
use chrono_tz::Tz;
use ghostr_core::time::{Clock, Timestamp};
use ghostr_store::memory::TimeRange;
use serde::{Deserialize, Serialize};

/// When a day ends.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CutoffPolicy {
    /// Local time of day, in minutes past midnight. Default 23:59.
    pub minute_of_day: u16,
    /// The identity's home zone, which decides the boundary.
    pub home_tz: Tz,
    /// Grace period after the cutoff before sealing runs.
    ///
    /// Lets an ingest that started before the cutoff finish, so a note written
    /// at 23:58 and synced at 00:01 still lands in the right day.
    pub grace_minutes: u16,
}

/// The window for one sequence.
///
/// Half-open `[previous_cutoff, cutoff)` on absolute instants.
#[must_use]
pub fn window_for(
    policy: &CutoffPolicy,
    date: NaiveDate,
    previous_cutoff: Option<Timestamp>,
) -> TimeRange {
    todo!("project the cutoff into UTC and build a half-open range from the previous one")
}

/// Every unsealed window between the last seal and now, oldest first.
///
/// The answer to a laptop that slept through three cutoffs. Each missed day
/// seals in order, because skipping them would leave gaps and backdating them
/// into one window would misattribute memories to the wrong day (SPEC I3).
#[must_use]
pub fn pending_windows(
    policy: &CutoffPolicy,
    clock: &dyn Clock,
    last_sealed: Option<(u64, Timestamp)>,
) -> Vec<PendingWindow> {
    todo!("walk cutoffs forward from the last seal to now")
}

/// One window awaiting a seal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PendingWindow {
    /// The sequence it will take.
    pub seq: u64,
    /// Its local date.
    pub date: NaiveDate,
    /// The zone in effect at its cutoff.
    pub tz: Tz,
    /// The absolute range.
    pub range: TimeRange,
}
