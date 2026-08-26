//! Deterministic clock and entropy.

use chrono_tz::Tz;
use ghostr_core::time::{Clock, Rng, Timestamp};

/// A clock that only moves when told to.
///
/// Lets a test walk a chain across a month, a DST boundary, or a westward
/// flight in microseconds.
///
/// Cloning shares the time rather than copying it, so a test can keep a handle
/// on the clock it handed to an engine — otherwise it could set the time once
/// and never move it again, which rules out every case that only appears when
/// time passes: an expiry, a streak, a rolling window.
#[derive(Debug, Clone)]
pub struct FixedClock {
    now: std::sync::Arc<std::sync::Mutex<Timestamp>>,
    tz: Tz,
}

impl FixedClock {
    /// A clock fixed at an instant.
    #[must_use]
    pub fn at(now: Timestamp, tz: Tz) -> Self {
        Self {
            now: std::sync::Arc::new(std::sync::Mutex::new(now)),
            tz,
        }
    }

    /// Moves the clock forward.
    ///
    /// # Panics
    ///
    /// Panics if the internal lock is poisoned, which can only happen if another
    /// test thread panicked while holding it.
    pub fn advance(&self, seconds: i64) {
        let mut now = self
            .now
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *now = Timestamp::new(
            now.utc_millis()
                .saturating_add(seconds.saturating_mul(1_000)),
            now.offset_seconds(),
        );
    }

    /// Moves the clock to just past the next cutoff.
    ///
    /// The common case in a pipeline test, and easy to get wrong by hand.
    pub fn advance_to_cutoff(&self, minute_of_day: u16) {
        use chrono::{NaiveTime, Offset as _, TimeZone as _};

        let mut now = self
            .now
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let minute = u32::from(minute_of_day.min(24 * 60 - 1));
        let Some(time) = NaiveTime::from_hms_opt(minute / 60, minute % 60, 0) else {
            return;
        };
        let Some(local) = self
            .tz
            .timestamp_millis_opt(now.utc_millis())
            .earliest()
            .map(|dt| dt.date_naive())
        else {
            return;
        };

        // Today's cutoff if it is still ahead, tomorrow's otherwise. "Advance"
        // must always move forward: a call that left the clock where it was
        // would make a pipeline test loop forever without saying why.
        for date in [local, local.succ_opt().unwrap_or(local)] {
            let Some(candidate) = self.tz.from_local_datetime(&date.and_time(time)).earliest()
            else {
                continue;
            };
            // One second past, so the cutoff has *passed* rather than being
            // exactly on it — a half-open window excludes its own end.
            let millis = candidate.timestamp_millis() + 1_000;
            if millis > now.utc_millis() {
                *now = Timestamp::new(millis, candidate.offset().fix().local_minus_utc());
                return;
            }
        }
    }
}

impl Clock for FixedClock {
    fn now(&self) -> Timestamp {
        *self
            .now
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn home_tz(&self) -> Tz {
        self.tz
    }
}

/// A reproducible RNG.
///
/// **Never use this outside tests.** It is a counter-based stream chosen for
/// reproducibility, not for unpredictability, and it lives in a crate that
/// cannot be a production dependency.
#[derive(Debug)]
pub struct SeededRng {
    state: std::sync::Mutex<u64>,
}

impl SeededRng {
    /// An RNG from a seed.
    #[must_use]
    pub fn from_seed(seed: u64) -> Self {
        Self {
            state: std::sync::Mutex::new(seed),
        }
    }
}

impl Rng for SeededRng {
    /// SplitMix64. Chosen because it is eight lines, has no state beyond a
    /// counter, and produces the same bytes on every platform — which is the
    /// entire requirement. It is emphatically not a CSPRNG, which is why this
    /// crate cannot be a production dependency.
    fn fill(&self, buf: &mut [u8]) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for chunk in buf.chunks_mut(8) {
            *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = *state;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^= z >> 31;
            let bytes = z.to_le_bytes();
            chunk.copy_from_slice(&bytes[..chunk.len()]);
        }
    }
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone as _;

    use super::*;

    /// 2026-08-24 08:00 UTC.
    const START: i64 = 1_787_558_400_000;

    fn clock(tz: Tz) -> FixedClock {
        FixedClock::at(Timestamp::new(START, 0), tz)
    }

    #[test]
    fn the_clock_only_moves_when_told_to() {
        let c = clock(Tz::UTC);
        assert_eq!(c.now().utc_millis(), START);
        assert_eq!(
            c.now().utc_millis(),
            START,
            "reading it does not advance it"
        );
        c.advance(3_600);
        assert_eq!(c.now().utc_millis(), START + 3_600_000);
    }

    #[test]
    fn advancing_to_a_cutoff_lands_just_past_it() {
        let c = clock(Tz::UTC);
        c.advance_to_cutoff(23 * 60 + 59);
        let at = Tz::UTC
            .timestamp_millis_opt(c.now().utc_millis())
            .earliest()
            .expect("valid");
        assert_eq!(
            at.format("%Y-%m-%d %H:%M:%S").to_string(),
            "2026-08-24 23:59:01"
        );
    }

    /// A half-open window excludes its own end, so the clock has to land *past*
    /// the cutoff for the day to be sealable.
    #[test]
    fn a_cutoff_that_has_already_passed_advances_to_tomorrow() {
        let c = clock(Tz::UTC);
        c.advance_to_cutoff(6 * 60); // 06:00 is behind 08:00
        let at = Tz::UTC
            .timestamp_millis_opt(c.now().utc_millis())
            .earliest()
            .expect("valid");
        assert_eq!(at.format("%Y-%m-%d %H:%M").to_string(), "2026-08-25 06:00");
    }

    /// Advancing must always move forward. A call that left the clock where it
    /// was would make a pipeline test loop without saying why.
    #[test]
    fn advancing_to_a_cutoff_always_moves_forward() {
        let c = clock(Tz::UTC);
        let mut previous = c.now().utc_millis();
        for _ in 0..5 {
            c.advance_to_cutoff(23 * 60 + 59);
            assert!(c.now().utc_millis() > previous);
            previous = c.now().utc_millis();
        }
    }

    /// The offset in effect travels with the instant, which is what makes a
    /// footage able to record "the zone was +07 that day" (SPEC §3.4).
    #[test]
    fn the_offset_of_the_zone_travels_with_the_instant() {
        let c = clock(Tz::Asia__Bangkok);
        c.advance_to_cutoff(23 * 60 + 59);
        assert_eq!(c.now().offset_seconds(), 7 * 3_600);
    }

    /// A DST boundary is the case cutoff logic is most likely to get wrong
    /// (SPEC Q11), so the clock has to be able to walk one.
    #[test]
    fn the_clock_walks_a_dst_boundary() {
        // Europe/London springs forward on 2026-03-29 at 01:00 local.
        let before = Tz::Europe__London
            .with_ymd_and_hms(2026, 3, 28, 12, 0, 0)
            .earliest()
            .expect("valid");
        let c = FixedClock::at(
            Timestamp::new(before.timestamp_millis(), 0),
            Tz::Europe__London,
        );

        c.advance_to_cutoff(23 * 60 + 59);
        assert_eq!(c.now().offset_seconds(), 0, "still GMT");
        c.advance_to_cutoff(23 * 60 + 59);
        assert_eq!(c.now().offset_seconds(), 3_600, "BST after the shift");
    }

    #[test]
    fn the_rng_is_reproducible_from_its_seed() {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        SeededRng::from_seed(42).fill(&mut a);
        SeededRng::from_seed(42).fill(&mut b);
        assert_eq!(a, b);
    }

    #[test]
    fn a_different_seed_gives_different_bytes() {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        SeededRng::from_seed(42).fill(&mut a);
        SeededRng::from_seed(43).fill(&mut b);
        assert_ne!(a, b);
    }

    /// Successive draws differ. A generator that returned the same salt twice
    /// would make two identical memories hash to the same leaf, which is the
    /// property salting exists to prevent (SPEC §7.2).
    #[test]
    fn successive_draws_differ() {
        let rng = SeededRng::from_seed(7);
        let mut first = [0u8; 32];
        let mut second = [0u8; 32];
        rng.fill(&mut first);
        rng.fill(&mut second);
        assert_ne!(first, second);
    }

    /// A buffer that is not a multiple of eight must still be filled entirely.
    #[test]
    fn a_short_buffer_is_filled_completely() {
        let rng = SeededRng::from_seed(1);
        let mut buf = [0u8; 10];
        rng.fill(&mut buf);
        assert!(buf.iter().any(|b| *b != 0), "something was written");

        // And the same seed reproduces it, tail included.
        let mut again = [0u8; 10];
        SeededRng::from_seed(1).fill(&mut again);
        assert_eq!(buf, again);
    }
}
