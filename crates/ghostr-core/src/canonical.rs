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
//! # How determinism is achieved
//!
//! `ciborium` gives definite lengths and smallest-integer encoding, but it
//! serializes struct fields in declaration order rather than sorted. So values
//! go through an intermediate [`ciborium::Value`], every map is sorted by its
//! *encoded key bytes* per RFC 8949 §4.2.1, and the result is written back out.
//! That extra pass is the difference between "deterministic in practice on this
//! build" and "deterministic by construction".
//!
//! # Rules enforced here
//!
//! - Map keys sorted by their encoded bytes.
//! - Definite-length arrays and maps only.
//! - Smallest possible integer encoding.
//! - No floating point. Scores and weights are hashed as fixed-point integers,
//!   because `f32` has multiple bit patterns for NaN and no guaranteed
//!   round-trip across platforms.

use ciborium::Value;
use serde::Serialize;

/// Scale for [`ratio_to_fixed`]: six decimal places, far finer than any ratio
/// in this system is meaningful to.
const RATIO_SCALE: f32 = 1_000_000.0;

/// Encodes a value as canonical CBOR.
///
/// # Errors
///
/// Returns [`Error::Canonical`](crate::Error::Canonical) if the value contains
/// something that cannot be canonically encoded — most often a float, which is
/// rejected on purpose rather than rounded.
pub fn to_canonical_cbor<T: Serialize>(value: &T) -> crate::Result<Vec<u8>> {
    let v = Value::serialized(value).map_err(|_| crate::Error::Canonical {
        reason: "value is not representable as CBOR",
    })?;
    let v = canonicalize(v)?;
    let mut out = Vec::new();
    ciborium::into_writer(&v, &mut out).map_err(|_| crate::Error::Canonical {
        reason: "CBOR encoding failed",
    })?;
    Ok(out)
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
    let v: Value = ciborium::from_reader(bytes).map_err(|_| crate::Error::Canonical {
        reason: "malformed CBOR",
    })?;
    // Re-encode and compare. Anything that does not round-trip byte for byte was
    // not canonical, and accepting it would give one value two commitments.
    let round_tripped = {
        let mut buf = Vec::new();
        let c = canonicalize(v.clone())?;
        ciborium::into_writer(&c, &mut buf).map_err(|_| crate::Error::Canonical {
            reason: "CBOR re-encoding failed",
        })?;
        buf
    };
    if round_tripped != bytes {
        return Err(crate::Error::Canonical {
            reason: "encoding is not canonical",
        });
    }
    v.deserialized().map_err(|_| crate::Error::Canonical {
        reason: "CBOR does not match the target type",
    })
}

/// Verifies bytes are canonical CBOR without decoding into a type.
///
/// # Errors
///
/// Returns [`Error::Canonical`](crate::Error::Canonical) if the bytes are
/// malformed or non-canonical.
pub fn verify_canonical(bytes: &[u8]) -> crate::Result<()> {
    let v: Value = ciborium::from_reader(bytes).map_err(|_| crate::Error::Canonical {
        reason: "malformed CBOR",
    })?;
    let mut buf = Vec::new();
    ciborium::into_writer(&canonicalize(v)?, &mut buf).map_err(|_| crate::Error::Canonical {
        reason: "CBOR re-encoding failed",
    })?;
    if buf == bytes {
        Ok(())
    } else {
        Err(crate::Error::Canonical {
            reason: "encoding is not canonical",
        })
    }
}

/// Recursively sorts map keys by encoded bytes and rejects floats.
fn canonicalize(v: Value) -> crate::Result<Value> {
    Ok(match v {
        // RFC 8949 §4.2.1: sort map entries by the byte sequence of the encoded
        // key. Sorting by the *decoded* key would order `1` and `"1"`
        // inconsistently across types.
        Value::Map(entries) => {
            let mut keyed = Vec::with_capacity(entries.len());
            for (k, val) in entries {
                let mut encoded = Vec::new();
                ciborium::into_writer(&k, &mut encoded).map_err(|_| crate::Error::Canonical {
                    reason: "map key is not encodable",
                })?;
                keyed.push((encoded, canonicalize(k)?, canonicalize(val)?));
            }
            keyed.sort_by(|a, b| a.0.cmp(&b.0));
            // Duplicate keys make a map ambiguous, so they are an error rather
            // than a last-write-wins merge.
            if keyed.windows(2).any(|w| w[0].0 == w[1].0) {
                return Err(crate::Error::Canonical {
                    reason: "duplicate map key",
                });
            }
            Value::Map(keyed.into_iter().map(|(_, k, v)| (k, v)).collect())
        }
        Value::Array(items) => Value::Array(
            items
                .into_iter()
                .map(canonicalize)
                .collect::<crate::Result<_>>()?,
        ),
        // Floats have multiple NaN bit patterns and no guaranteed cross-platform
        // round trip, so a float in a hashed structure is a commitment bug.
        // Rejected rather than rounded, so it surfaces at the type that
        // introduced it.
        Value::Float(_) => {
            return Err(crate::Error::Canonical {
                reason: "floats are not canonically encodable",
            });
        }
        other => other,
    })
}

/// Converts a ratio in `0.0..=1.0` to the fixed-point form used in preimages.
///
/// Scores, confidences, and weights are `f32` in memory because that is what the
/// math wants, and fixed-point on the wire because that is what hashing needs.
///
/// # Errors
///
/// Returns [`Error::OutOfRange`](crate::Error::OutOfRange) if `value` is outside
/// `0.0..=1.0` or is not finite.
pub fn ratio_to_fixed(value: f32, field: &'static str) -> crate::Result<u32> {
    if !value.is_finite() || !(0.0..=1.0).contains(&value) {
        return Err(crate::Error::OutOfRange { field });
    }
    // `round` rather than truncation so the mapping is symmetric and 1.0 lands
    // exactly on the scale rather than one below it.
    Ok((value * RATIO_SCALE).round() as u32)
}

/// Converts a signed ratio in `-1.0..=1.0` to fixed point, offset to stay
/// unsigned so the encoding has no sign-representation ambiguity.
///
/// # Errors
///
/// Returns [`Error::OutOfRange`](crate::Error::OutOfRange) if `value` is outside
/// `-1.0..=1.0` or is not finite.
pub fn signed_ratio_to_fixed(value: f32, field: &'static str) -> crate::Result<u32> {
    if !value.is_finite() || !(-1.0..=1.0).contains(&value) {
        return Err(crate::Error::OutOfRange { field });
    }
    Ok(((value + 1.0) * RATIO_SCALE).round() as u32)
}

/// Inverse of [`ratio_to_fixed`].
#[must_use]
pub fn fixed_to_ratio(fixed: u32) -> f32 {
    fixed as f32 / RATIO_SCALE
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    #[test]
    fn map_keys_are_sorted_by_encoded_bytes() {
        // Two maps with the same entries inserted in opposite orders must encode
        // identically, or one logical record would have two commitments.
        let mut a = BTreeMap::new();
        a.insert("zebra", 1u32);
        a.insert("ant", 2u32);
        let mut b = BTreeMap::new();
        b.insert("ant", 2u32);
        b.insert("zebra", 1u32);
        assert_eq!(
            to_canonical_cbor(&a).expect("encode a"),
            to_canonical_cbor(&b).expect("encode b")
        );
    }

    #[test]
    fn shorter_keys_sort_first() {
        // RFC 8949 §4.2.1 orders by encoded bytes, and a shorter text string has
        // a smaller head byte, so "z" precedes "aa".
        let mut m = BTreeMap::new();
        m.insert("aa", 1u32);
        m.insert("z", 2u32);
        let bytes = to_canonical_cbor(&m).expect("encode");
        let z_at = bytes.windows(1).position(|w| w == b"z").expect("z present");
        let aa_at = bytes
            .windows(2)
            .position(|w| w == b"aa")
            .expect("aa present");
        assert!(z_at < aa_at, "shorter key should sort first");
    }

    #[test]
    fn floats_are_rejected() {
        let err = to_canonical_cbor(&1.5f64).expect_err("float must be rejected");
        assert!(matches!(err, crate::Error::Canonical { .. }));
    }

    #[test]
    fn round_trip_preserves_value() {
        let value = vec![1u32, 2, 3];
        let bytes = to_canonical_cbor(&value).expect("encode");
        let back: Vec<u32> = from_canonical_cbor(&bytes).expect("decode");
        assert_eq!(value, back);
    }

    #[test]
    fn non_canonical_input_is_rejected() {
        // An indefinite-length array (0x9f ... 0xff) decodes fine but is not
        // canonical, so it must not be accepted.
        let indefinite = [0x9f, 0x01, 0x02, 0xff];
        assert!(verify_canonical(&indefinite).is_err());
        assert!(from_canonical_cbor::<Vec<u32>>(&indefinite).is_err());
    }

    #[test]
    fn ratio_conversion_round_trips_and_bounds() {
        for v in [0.0f32, 0.5, 1.0] {
            let fixed = ratio_to_fixed(v, "test").expect("in range");
            assert!((fixed_to_ratio(fixed) - v).abs() < 1e-6);
        }
        assert!(ratio_to_fixed(1.5, "test").is_err());
        assert!(ratio_to_fixed(f32::NAN, "test").is_err());
        assert!(signed_ratio_to_fixed(-1.0, "test").is_ok());
        assert!(signed_ratio_to_fixed(-1.5, "test").is_err());
    }
}
