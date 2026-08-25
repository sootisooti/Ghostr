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
    let end = cutoff_instant(policy, date);
    // The previous cutoff, not "midnight minus a day": on a day whose length was
    // not 24 hours, the two differ, and only the first leaves no gap.
    let start =
        previous_cutoff.unwrap_or_else(|| cutoff_instant(policy, date.pred_opt().unwrap_or(date)));
    TimeRange { start, end }
}

/// The absolute instant a local date's cutoff falls at.
///
/// A cutoff minute can be ambiguous across a DST fold and absent across a
/// spring-forward gap. Taking the earliest candidate in both cases makes the
/// choice deterministic rather than dependent on which branch a library happens
/// to return — and determinism is what stops the same day producing two windows,
/// and therefore two roots.
#[must_use]
pub fn cutoff_instant(policy: &CutoffPolicy, date: NaiveDate) -> Timestamp {
    use chrono::{NaiveTime, TimeZone as _};

    let minute = u32::from(policy.minute_of_day.min(24 * 60 - 1));
    let local = date
        .and_time(NaiveTime::from_hms_opt(minute / 60, minute % 60, 0).unwrap_or(NaiveTime::MIN));
    let millis = policy
        .home_tz
        .from_local_datetime(&local)
        .earliest()
        .map_or(0, |dt| dt.timestamp_millis());
    Timestamp::new(millis, 0)
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
    let now = clock.now();
    // The grace period delays sealing, so a cutoff that has passed but whose
    // grace has not is not yet pending: a note written at 23:58 and synced at
    // 00:01 still belongs to the day it was written in.
    let sealable_before = now.utc_millis() - i64::from(policy.grace_minutes) * 60_000;

    let (mut seq, mut previous) = match last_sealed {
        Some((seq, cutoff)) => (seq + 1, cutoff),
        None => {
            // Nothing sealed: start from the day containing `now`, so a fresh
            // vault seals one day rather than every day since the epoch.
            let today = date_at(policy, now);
            let first = today.pred_opt().unwrap_or(today);
            (1, cutoff_instant(policy, first.pred_opt().unwrap_or(first)))
        }
    };

    let mut out = Vec::new();
    let mut date = date_at(policy, previous);
    // Bounded so a clock jumped years forward cannot produce an unbounded list.
    // Ten years of catch-up is far past any real "the laptop was asleep" case.
    for _ in 0..3_660 {
        date = match date.succ_opt() {
            Some(d) => d,
            None => break,
        };
        let end = cutoff_instant(policy, date);
        if end.utc_millis() > sealable_before {
            break;
        }
        out.push(PendingWindow {
            seq,
            date,
            tz: policy.home_tz,
            range: TimeRange {
                start: previous,
                end,
            },
        });
        previous = end;
        seq += 1;
    }
    out
}

/// Which cutoff-day an instant falls in, in the home zone.
fn date_at(policy: &CutoffPolicy, at: Timestamp) -> NaiveDate {
    use chrono::TimeZone as _;

    policy
        .home_tz
        .timestamp_millis_opt(at.utc_millis())
        .earliest()
        .map(|dt| dt.date_naive())
        .unwrap_or_default()
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

#[cfg(test)]
mod tests {
    use chrono_tz::Tz;

    use super::*;

    struct At(i64);
    impl Clock for At {
        fn now(&self) -> Timestamp {
            Timestamp::new(self.0, 0)
        }
        fn home_tz(&self) -> Tz {
            Tz::UTC
        }
    }

    fn policy(tz: Tz) -> CutoffPolicy {
        CutoffPolicy {
            minute_of_day: 23 * 60 + 59,
            home_tz: tz,
            grace_minutes: 0,
        }
    }

    fn date(y: i32, m: u32, d: u32) -> NaiveDate {
        NaiveDate::from_ymd_opt(y, m, d).expect("valid date")
    }

    #[test]
    fn a_window_is_half_open_and_ends_at_the_cutoff() {
        let p = policy(Tz::UTC);
        let w = window_for(&p, date(2026, 8, 25), None);
        assert_eq!(w.end, cutoff_instant(&p, date(2026, 8, 25)));
        assert_eq!(w.start, cutoff_instant(&p, date(2026, 8, 24)));
        assert!(w.start.utc_millis() < w.end.utc_millis());
    }

    /// The property that keeps the chain gapless: one day's start is the
    /// previous day's end, exactly, with no instant in between.
    #[test]
    fn consecutive_windows_leave_no_gap_and_no_overlap() {
        let p = policy(Tz::UTC);
        let first = window_for(&p, date(2026, 8, 25), None);
        let second = window_for(&p, date(2026, 8, 26), Some(first.end));
        assert_eq!(first.end, second.start);
    }

    /// SPEC Q11. A westward flight makes a long day, and the window shows it
    /// rather than hiding it — but it is still exactly one window.
    #[test]
    fn a_dst_shift_changes_a_days_length_without_gapping_it() {
        // Europe/London springs forward on 2026-03-29.
        let p = policy(Tz::Europe__London);
        let before = window_for(&p, date(2026, 3, 28), None);
        let across = window_for(&p, date(2026, 3, 29), Some(before.end));
        let after = window_for(&p, date(2026, 3, 30), Some(across.end));

        let length = |w: &TimeRange| w.end.utc_millis() - w.start.utc_millis();
        assert_eq!(length(&across), 23 * 3_600_000, "a 23-hour day");
        assert_eq!(across.start, before.end);
        assert_eq!(after.start, across.end);
    }

    #[test]
    fn a_laptop_that_slept_through_three_cutoffs_seals_each_in_order() {
        let p = policy(Tz::UTC);
        let last = cutoff_instant(&p, date(2026, 8, 25));
        // Two days later, well past the cutoff.
        let now = cutoff_instant(&p, date(2026, 8, 28));
        let pending = pending_windows(&p, &At(now.utc_millis()), Some((7, last)));

        assert_eq!(pending.len(), 3);
        assert_eq!(pending[0].seq, 8);
        assert_eq!(pending[0].date, date(2026, 8, 26));
        assert_eq!(pending[2].seq, 10);
        assert_eq!(pending[2].date, date(2026, 8, 28));
        // Contiguous, in order.
        assert_eq!(pending[0].range.start, last);
        assert_eq!(pending[1].range.start, pending[0].range.end);
        assert_eq!(pending[2].range.start, pending[1].range.end);
    }

    /// A note written at 23:58 and synced at 00:01 must still land in the day it
    /// was written in, which is what the grace period buys.
    #[test]
    fn the_grace_period_holds_a_day_open() {
        let mut p = policy(Tz::UTC);
        p.grace_minutes = 30;
        let last = cutoff_instant(&p, date(2026, 8, 25));
        // Ten minutes past the next cutoff: inside the grace period.
        let now = cutoff_instant(&p, date(2026, 8, 26)).utc_millis() + 10 * 60_000;
        assert!(pending_windows(&p, &At(now), Some((7, last))).is_empty());

        // Forty minutes past: the grace has expired.
        let later = cutoff_instant(&p, date(2026, 8, 26)).utc_millis() + 40 * 60_000;
        assert_eq!(pending_windows(&p, &At(later), Some((7, last))).len(), 1);
    }

    /// A fresh vault seals one day, not every day since the epoch.
    #[test]
    fn a_vault_with_nothing_sealed_does_not_backfill_history() {
        let p = policy(Tz::UTC);
        let now = cutoff_instant(&p, date(2026, 8, 25)).utc_millis() + 3_600_000;
        let pending = pending_windows(&p, &At(now), None);
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].seq, 1);
        assert_eq!(pending[0].date, date(2026, 8, 25));
    }

    #[test]
    fn nothing_is_pending_before_the_first_cutoff_passes() {
        let p = policy(Tz::UTC);
        let last = cutoff_instant(&p, date(2026, 8, 25));
        let now = last.utc_millis() + 60_000;
        assert!(pending_windows(&p, &At(now), Some((7, last))).is_empty());
    }

    /// A clock that jumped forward years must not produce an unbounded list.
    #[test]
    fn a_clock_jumped_far_forward_is_bounded() {
        let p = policy(Tz::UTC);
        let last = cutoff_instant(&p, date(2000, 1, 1));
        let now = cutoff_instant(&p, date(2200, 1, 1));
        assert!(pending_windows(&p, &At(now.utc_millis()), Some((1, last))).len() <= 3_660);
    }
}
