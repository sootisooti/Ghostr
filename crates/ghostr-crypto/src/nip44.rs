//! NIP-44 v2 payload encryption.
//!
//! Used for two things that look the same on the wire and mean different things:
//! ordinary encryption to another party, and **self-encryption** — deriving the
//! conversation key from one's own keypair — which is how Ghostr stores private
//! app data on relays that can never read it (SPEC §10.3).
//!
//! # What this does not hide
//!
//! NIP-44 encrypts content. It does not hide the author pubkey, the event kind,
//! the `d` tag, the `created_at`, or the ciphertext length. A relay sees all of
//! those and can infer a great deal from the pattern alone — a daily cadence of
//! same-kind events says "this person is alive, journaling, and stopped on the
//! 14th" (THREAT_MODEL §T2). [`pad_to_bucket`] blunts the length signal;
//! NIP-59 gift wrap, in `ghostr-nostr`, is what hides the rest.

use crate::secret::SecretBytes;

/// The NIP-44 version this build implements.
pub const VERSION: u8 = 2;

/// A NIP-44 conversation key: the ECDH-derived shared secret for a key pair.
///
/// For self-encryption both halves are the same identity, which yields a stable
/// key only that identity can derive.
#[derive(Debug)]
pub struct ConversationKey(SecretBytes<32>);

impl ConversationKey {
    /// Borrows the raw key.
    #[must_use]
    pub(crate) fn expose(&self) -> &[u8; 32] {
        self.0.expose()
    }
}

/// Encrypts `plaintext` to `recipient`.
///
/// # Errors
///
/// Returns an error if the conversation key cannot be derived or the nonce
/// cannot be generated.
pub fn encrypt(key: &ConversationKey, plaintext: &[u8], nonce: &[u8; 32]) -> crate::Result<String> {
    todo!("HKDF-expand the conversation key, ChaCha20 encrypt, HMAC-SHA256, base64")
}

/// Decrypts a NIP-44 payload.
///
/// The MAC is verified before decryption is attempted, and every failure mode
/// collapses to one error variant. A caller must not be able to distinguish a
/// bad MAC from bad padding from a wrong key: that distinction is precisely what
/// an oracle attack needs.
///
/// # Errors
///
/// Returns [`Error::DecryptFailed`](crate::Error::DecryptFailed) for any
/// failure, or
/// [`Error::UnsupportedVersion`](crate::Error::UnsupportedVersion) if the
/// payload declares a version this build does not implement.
pub fn decrypt(key: &ConversationKey, payload: &str) -> crate::Result<Vec<u8>> {
    todo!("base64-decode, check version, verify MAC in constant time, then decrypt")
}

/// Pads a plaintext length up to the next NIP-44 bucket.
///
/// Length is metadata. Without padding, a 40-word day and a 4000-word day are
/// trivially distinguishable to a relay operator watching one pubkey over time.
#[must_use]
pub fn pad_to_bucket(len: usize) -> usize {
    todo!("round up to the next NIP-44 padding bucket")
}
