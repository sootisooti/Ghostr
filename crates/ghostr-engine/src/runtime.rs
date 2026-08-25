//! The real [`Clock`] and [`Rng`].
//!
//! `clippy.toml` bans the underlying constructors workspace-wide so that time
//! and entropy enter the system through traits rather than wherever they are
//! convenient (ARCHITECTURE §4.7). **This module holds the workspace's only
//! exceptions**, each behind an explicit `allow` with a comment, which is what
//! makes them greppable and keeps them in one file.

use chrono::Offset as _;
use chrono_tz::Tz;
use ghostr_core::time::{Clock, Rng, Timestamp};

/// The system clock.
#[derive(Debug, Clone, Copy)]
pub struct SystemClock {
    home_tz: Tz,
}

impl SystemClock {
    /// A clock reporting `home_tz` as the sealing zone.
    ///
    /// The home zone rather than the ambient one: cutoffs are decided by where
    /// the user lives, not where they are standing, so a trip does not silently
    /// reshape their days (SPEC Q11).
    #[must_use]
    pub const fn new(home_tz: Tz) -> Self {
        Self { home_tz }
    }
}

impl Clock for SystemClock {
    fn now(&self) -> Timestamp {
        // ARCHITECTURE §4.7: the composition root is the one place allowed to
        // read the system clock. Everywhere else takes a `&dyn Clock`.
        #[allow(clippy::disallowed_methods)]
        let now = std::time::SystemTime::now();

        let millis = now
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
            .unwrap_or(0);

        // The offset is looked up from the home zone rather than from the OS
        // locale, so it stays consistent with the zone that decides cutoffs.
        let offset: i64 = ghostr_core::time::Timestamp::new(millis, 0)
            .to_utc()
            .with_timezone(&self.home_tz)
            .offset()
            .fix()
            .local_minus_utc()
            .into();
        Timestamp::new(millis, i32::try_from(offset).unwrap_or(0))
    }

    fn home_tz(&self) -> Tz {
        self.home_tz
    }
}

/// The operating system CSPRNG.
///
/// Used for seed entropy, memory salts, and nonces. Nothing else in the tree
/// constructs one.
#[derive(Debug, Clone, Copy, Default)]
pub struct OsRng;

impl Rng for OsRng {
    fn fill(&self, buf: &mut [u8]) {
        // `getrandom` is reached through secp256k1's re-export rather than as a
        // direct dependency, keeping the tree one crate smaller.
        secp256k1::rand::RngCore::fill_bytes(&mut secp256k1::rand::rng(), buf);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_clock_reports_the_home_zone_offset() {
        let bangkok: Tz = "Asia/Bangkok".parse().expect("zone");
        let clock = SystemClock::new(bangkok);
        assert_eq!(clock.home_tz(), bangkok);
        // Bangkok has no DST, so its offset is always +07:00.
        assert_eq!(clock.now().offset_seconds(), 7 * 3600);
    }

    #[test]
    fn the_rng_produces_varying_output() {
        let rng = OsRng;
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        rng.fill(&mut a);
        rng.fill(&mut b);
        assert_ne!(a, b, "two draws should differ");
        assert_ne!(a, [0u8; 32], "output should not be all zeroes");
    }
}
