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

// There is deliberately no `pad_content` here.
//
// The scaffold planned one — "pad ciphertext up to a bucket boundary" — and it
// would have been both redundant and destructive. NIP-44 v2 pads the
// *plaintext* to a bucket before encrypting, so ciphertext length is already
// quantised by the time this module could see it; appending to the base64
// payload afterwards would only make it fail to decrypt.
//
// `nip44_bucketing_already_quantises_length` is what keeps that claim honest.
// Deleting the function rather than leaving it as a no-op is CLAUDE.md §9:
// a boundary that no longer enforces anything should be merged away, not kept
// out of politeness.

/// Chooses a jittered publish time.
///
/// Publishing at the sealing instant discloses the user's cutoff hour, and
/// therefore their approximate timezone and daily rhythm. Jitter is drawn from
/// the caller's [`Rng`](ghostr_core::time::Rng) so the choice is reproducible in
/// tests.
#[must_use]
pub fn jitter_created_at(base: u64, rng: &dyn ghostr_core::time::Rng, window_secs: u32) -> u64 {
    if window_secs == 0 {
        return base;
    }

    let mut bytes = [0u8; 8];
    rng.fill(&mut bytes);

    // Only ever later, never earlier. A `created_at` before the seal would claim
    // the event existed before the footage it commits to, and relays reject
    // timestamps too far in the past as readily as ones in the future.
    //
    // Modulo bias is real here and harmless: the window is at most 2^32 and the
    // draw is 2^64, so the skew is on the order of 2^-32 — far below what a
    // relay could distinguish from the clock itself.
    base.saturating_add(u64::from_be_bytes(bytes) % u64::from(window_secs))
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
    // Left unimplemented, and the signature is why — SPEC §14 Q20.
    //
    // NIP-59 is three layers: a rumor, a seal (kind 13) encrypted to the
    // recipient and signed by the real author, and a wrap (kind 1059) encrypted
    // and signed by a *throwaway* key. This signature can produce none of them.
    // It has no recipient, so there is nobody to encrypt to; no `Signer`, so the
    // seal cannot be signed; and it returns an `UnsignedEvent`, though the wrap
    // must be signed by a key that exists only inside this call.
    //
    // Deriving that key here from `ephemeral_entropy` is the obvious shortcut
    // and the one thing that is not allowed: ARCHITECTURE §3 rule 4 puts secret
    // key bytes in `ghostr-crypto` and nowhere else. Closing this means giving
    // `Signer` an ephemeral-key operation, which is a decision about the crypto
    // seam rather than a gap with one right answer — so it is a question, not a
    // silent choice (CLAUDE.md §9).
    todo!("SPEC Q20: needs an ephemeral-key operation on Signer")
}

#[cfg(test)]
mod tests {
    use ghostr_testkit::time::SeededRng;

    use super::*;

    #[test]
    fn jitter_never_moves_a_publish_earlier() {
        // A `created_at` before the seal claims the event predates the footage
        // it commits to, and relays reject far-past timestamps as readily as
        // far-future ones.
        let base = 1_756_252_800;
        for seed in 0..64 {
            let rng = SeededRng::from_seed(seed);
            assert!(jitter_created_at(base, &rng, 3600) >= base);
        }
    }

    #[test]
    fn jitter_stays_inside_the_window() {
        let base = 1_756_252_800;
        for seed in 0..64 {
            let rng = SeededRng::from_seed(seed);
            let jittered = jitter_created_at(base, &rng, 3600);
            assert!(jittered < base + 3600, "{jittered} outside the window");
        }
    }

    #[test]
    fn a_zero_window_is_the_identity() {
        // Guarded rather than left to `% 0`, which panics.
        let rng = SeededRng::from_seed(7);
        assert_eq!(jitter_created_at(1_756_252_800, &rng, 0), 1_756_252_800);
    }

    #[test]
    fn jitter_actually_moves_the_timestamp() {
        // A jitter that always returns `base` would pass every bound above while
        // disclosing the cutoff hour exactly as before.
        let base = 1_756_252_800;
        let seen: std::collections::HashSet<u64> = (0..32)
            .map(|seed| jitter_created_at(base, &SeededRng::from_seed(seed), 3600))
            .collect();
        assert!(seen.len() > 16, "only {} distinct offsets", seen.len());
    }

    #[test]
    fn jitter_is_reproducible_under_one_seed() {
        // CLAUDE.md §6: a flaky test here would be a design bug, not a retry
        // candidate.
        let a = jitter_created_at(100, &SeededRng::from_seed(9), 3600);
        let b = jitter_created_at(100, &SeededRng::from_seed(9), 3600);
        assert_eq!(a, b);
    }

    /// The claim that justifies deleting `pad_content`.
    ///
    /// NIP-44 v2 pads the plaintext to a bucket before encrypting, so ciphertext
    /// length is already quantised — two messages of different length inside one
    /// bucket are indistinguishable by length on the wire. If this ever stops
    /// holding, the padding has to come back, and this test is what says so.
    #[test]
    fn nip44_bucketing_already_quantises_length() {
        use ghostr_core::identity::PublicKey;
        use ghostr_crypto::nip44::{ConversationKey, encrypt};

        let peer =
            PublicKey::from_hex("3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d")
                .expect("hex");
        let key = ConversationKey::derive(&[7u8; 32], &peer).expect("derive");

        // Both land in the 32-byte bucket: a terse day and a wordier one.
        let terse = encrypt(&key, b"ok", &[1u8; 32]).expect("encrypt");
        let wordier = encrypt(&key, b"a much longer line", &[1u8; 32]).expect("encrypt");
        assert_eq!(terse.len(), wordier.len());

        // And the buckets are coarse: 33 bytes does not get its own length.
        let a = encrypt(&key, &[b'x'; 33], &[1u8; 32]).expect("encrypt");
        let b = encrypt(&key, &[b'x'; 48], &[1u8; 32]).expect("encrypt");
        assert_eq!(a.len(), b.len());

        // It is bucketing, not a fixed size: a genuinely long day is longer.
        let long = encrypt(&key, &[b'x'; 5000], &[1u8; 32]).expect("encrypt");
        assert!(long.len() > terse.len());
    }
}
