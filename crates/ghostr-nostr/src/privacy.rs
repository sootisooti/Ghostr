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

use ghostr_core::identity::{KeyRef, PublicKey};
use ghostr_crypto::Signer;
use ghostr_crypto::event::{SignedEvent, UnsignedEvent};
use ghostr_crypto::signer::GiftWrapEntropy;
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

/// Wraps an event in NIP-59 gift wrap, hiding its author from relays.
///
/// The cryptography is delegated to [`Signer::gift_wrap`]: the throwaway key
/// that signs the outer layer is what hides the author, and it is born and
/// zeroized inside `ghostr-crypto` (SPEC §14 Q20). This crate keeps the policy
/// decision — [`PrivacyMode::GiftWrapped`] — and none of the key material,
/// which is the split every other seam in this tree uses.
///
/// # Errors
///
/// Returns an error if the signer refuses. A **remote signer always will**:
/// NIP-46 has no gift-wrap method, so choosing a bunker and choosing gift wrap
/// are mutually exclusive today, and the caller is told rather than quietly
/// given an event whose author a relay can read.
pub async fn gift_wrap(
    signer: &dyn Signer,
    key: KeyRef,
    recipient: &PublicKey,
    rumor: &UnsignedEvent,
    entropy: GiftWrapEntropy,
) -> crate::Result<SignedEvent> {
    Ok(signer.gift_wrap(key, recipient, rumor, entropy).await?)
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
