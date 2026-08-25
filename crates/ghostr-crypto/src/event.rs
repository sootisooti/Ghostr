//! The minimal nostr event shape that signing operates on.
//!
//! Deliberately small, and deliberately here rather than in `ghostr-nostr`:
//! [`Signer`](crate::Signer) needs something to sign, and `ghostr-crypto` cannot
//! depend on `ghostr-nostr` without inverting the dependency direction. The
//! relay codec, subscription handling, and Ghostr's own event kinds live in
//! `ghostr-nostr`, which depends on this.

use ghostr_core::hash::Hash32;
use ghostr_core::identity::PublicKey;
use serde::{Deserialize, Serialize};

/// A nostr event before it has been signed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnsignedEvent {
    /// Author.
    pub pubkey: PublicKey,
    /// Seconds since the Unix epoch, as nostr requires.
    pub created_at: u64,
    /// Event kind.
    pub kind: u16,
    /// Tags, each a list of strings.
    pub tags: Vec<Vec<String>>,
    /// Content. Ciphertext for every private Ghostr kind (SPEC I9).
    pub content: String,
}

impl UnsignedEvent {
    /// Computes the NIP-01 event id.
    ///
    /// The id is `sha256` of a canonical JSON array — this is nostr's rule, not
    /// ours, and it is the one place in the tree where a hash is taken over JSON
    /// rather than canonical CBOR. Keep the two straight: this hash is for
    /// protocol interoperability, never for the commitment chain.
    #[must_use]
    pub fn id(&self) -> Hash32 {
        todo!("serialize per NIP-01 and take the sha256")
    }
}

/// A BIP-340 Schnorr signature.
///
/// Serialized as lowercase hex rather than as a byte array: that is the form
/// nostr puts on the wire, and serde has no array impls past 32 elements anyway.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Signature([u8; 64]);

impl Serialize for Signature {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        todo!("serialize as a lowercase hex string")
    }
}

impl<'de> Deserialize<'de> for Signature {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        todo!("parse exactly 128 lowercase hex digits")
    }
}

impl Signature {
    /// Wraps 64 raw bytes.
    #[must_use]
    pub fn from_bytes(bytes: [u8; 64]) -> Self {
        Self(bytes)
    }

    /// The raw bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }

    /// Lowercase hex.
    #[must_use]
    pub fn to_hex(&self) -> String {
        todo!("lowercase hex-encode the signature")
    }
}

impl core::fmt::Debug for Signature {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        todo!("write the lowercase hex signature")
    }
}

/// A signed nostr event, ready to publish.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedEvent {
    /// The event id.
    pub id: Hash32,
    /// The unsigned body.
    #[serde(flatten)]
    pub event: UnsignedEvent,
    /// The signature over [`SignedEvent::id`].
    pub sig: Signature,
}

impl SignedEvent {
    /// Verifies that the id matches the body and the signature matches the id.
    ///
    /// Both halves matter. Checking the signature alone would accept an event
    /// whose id was computed over different content.
    ///
    /// # Errors
    ///
    /// Returns [`Error::BadSignature`](crate::Error::BadSignature) if either
    /// check fails.
    pub fn verify(&self) -> crate::Result<()> {
        todo!("recompute the id, then verify the Schnorr signature over it")
    }
}
