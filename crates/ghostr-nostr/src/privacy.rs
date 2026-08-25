//! Metadata mitigations, and an honest account of their limits.
//!
//! NIP-44 encrypts content. It does not hide the author pubkey, the event kind,
//! the `d` tag, the `created_at`, or the ciphertext length. This module holds
//! what can be done about the rest.
//!
//! **None of it removes the liveness signal.** Padding and jitter blunt the
//! edges of "this person journals daily and stopped on the 14th"; they do not
//! erase it. That is why anchor receipts default to local-only rather than
//! relying on these measures (SPEC Q5, THREAT_MODEL §T2).

use ghostr_crypto::event::UnsignedEvent;
use serde::{Deserialize, Serialize};

/// How much metadata protection a publish applies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum PrivacyMode {
    /// NIP-44 content encryption with padding and jitter.
    ///
    /// Author, kind, and `d` tag remain visible, which is what makes the event
    /// findable by the user's own other devices.
    Standard,
    /// NIP-59 gift wrap with an ephemeral sender key.
    ///
    /// Hides kind and author too, at the cost of discoverability: the event can
    /// no longer be found by filtering on the user's pubkey, so restore needs
    /// another way to locate it.
    GiftWrapped,
}

/// Pads ciphertext up to a bucket boundary.
///
/// Length is metadata. Without padding, a terse day and a long one are trivially
/// distinguishable to a relay watching one pubkey over time.
#[must_use]
pub fn pad_content(content: &str) -> String {
    todo!("pad to the next NIP-44 bucket")
}

/// Chooses a jittered publish time.
///
/// Publishing at the sealing instant discloses the user's cutoff hour, and
/// therefore their approximate timezone and daily rhythm. Jitter is drawn from
/// the caller's [`Rng`](ghostr_core::time::Rng) so the choice is reproducible in
/// tests.
#[must_use]
pub fn jitter_created_at(base: u64, rng: &dyn ghostr_core::time::Rng, window_secs: u32) -> u64 {
    todo!("offset `base` by a uniform draw within the window")
}

/// Wraps an event in NIP-59 gift wrap under an ephemeral key.
///
/// # Errors
///
/// Returns an error if sealing or wrapping fails.
pub fn gift_wrap(
    event: &UnsignedEvent,
    ephemeral_entropy: &[u8; 32],
) -> crate::Result<UnsignedEvent> {
    todo!("seal the rumor, then wrap it under an ephemeral key per NIP-59")
}
