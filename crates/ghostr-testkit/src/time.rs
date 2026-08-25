//! Deterministic clock and entropy.

use chrono_tz::Tz;
use ghostr_core::time::{Clock, Rng, Timestamp};

/// A clock that only moves when told to.
///
/// Lets a test walk a chain across a month, a DST boundary, or a westward
/// flight in microseconds.
#[derive(Debug)]
pub struct FixedClock {
    now: std::sync::Mutex<Timestamp>,
    tz: Tz,
}

impl FixedClock {
    /// A clock fixed at an instant.
    #[must_use]
    pub fn at(now: Timestamp, tz: Tz) -> Self {
        Self {
            now: std::sync::Mutex::new(now),
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
        todo!("add `seconds` to the current instant")
    }

    /// Moves the clock to just past the next cutoff.
    ///
    /// The common case in a pipeline test, and easy to get wrong by hand.
    pub fn advance_to_cutoff(&self, minute_of_day: u16) {
        todo!("advance to the next occurrence of the cutoff minute in `tz`")
    }
}

impl Clock for FixedClock {
    fn now(&self) -> Timestamp {
        todo!("return the stored instant")
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
    fn fill(&self, buf: &mut [u8]) {
        todo!("fill from a reproducible counter-based stream")
    }
}
