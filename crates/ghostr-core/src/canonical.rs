//! Deterministic CBOR — the only serialization that is ever hashed.
//!
//! Two serialization paths exist in this project and they are never conflated
//! (CLAUDE.md §5):
//!
//! - **Canonical CBOR** (RFC 8949 §4.2 core deterministic encoding) for anything
//!   that gets hashed.
//! - Serde JSON for config, the local API, and nostr event content.
//!
//! Hashing JSON would be a latent disaster: map ordering, float formatting, and
//! whitespace are all unconstrained, so two runs can serialize one value two
//! ways and commit to two different digests.
//!
//! # Rules enforced here
//!
//! - Map keys sorted by their encoded bytes.
//! - Definite-length arrays and maps only.
//! - Smallest possible integer encoding.
//! - No floating point in hashed structures. Scores and weights are hashed as
//!   fixed-point integers, because `f32` has multiple bit patterns for NaN and
//!   no guaranteed round-trip across platforms.

use serde::Serialize;

/// Encodes a value as canonical CBOR.
///
/// # Errors
///
/// Returns [`Error::Canonical`](crate::Error::Canonical) if the value contains
/// something that cannot be canonically encoded — most often a float, which is
/// rejected on purpose rather than rounded.
pub fn to_canonical_cbor<T: Serialize>(value: &T) -> crate::Result<Vec<u8>> {
    todo!("encode as RFC 8949 deterministic CBOR, rejecting floats")
}

/// Decodes canonical CBOR, rejecting any encoding that is not canonical.
///
/// Strictness is the point. Accepting a non-canonical encoding of a value would
/// let one logical record have two byte representations, and therefore two
/// commitments.
///
/// # Errors
///
/// Returns [`Error::Canonical`](crate::Error::Canonical) if the bytes are
/// malformed or merely non-canonical.
pub fn from_canonical_cbor<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> crate::Result<T> {
    todo!("decode CBOR and verify the encoding was canonical")
}

/// Converts a ratio in `0.0..=1.0` to the fixed-point form used in preimages.
///
/// Scores, confidences, and weights are `f32` in memory because that is what the
/// math wants, and fixed-point on the wire because that is what hashing needs.
/// The scale is 10^6, giving six decimal places — far finer than any of these
/// quantities is meaningful to.
///
/// # Errors
///
/// Returns [`Error::OutOfRange`](crate::Error::OutOfRange) if `value` is outside
/// `0.0..=1.0` or is not finite.
pub fn ratio_to_fixed(value: f32, field: &'static str) -> crate::Result<u32> {
    todo!("validate the range and scale by 1_000_000")
}

/// Inverse of [`ratio_to_fixed`].
#[must_use]
pub fn fixed_to_ratio(fixed: u32) -> f32 {
    todo!("divide by 1_000_000")
}
