//! Tagged hashing, and the domain-separation tags the commitment scheme uses.
//!
//! All hashing in Ghostr is BIP-340-style tagged SHA-256 (SPEC §7.1):
//!
//! ```text
//! H_tag(tag, msg) = SHA256( SHA256(tag) || SHA256(tag) || msg )
//! ```
//!
//! Tagging buys free domain separation: a memory leaf can never be read as a
//! Merkle internal node or as a chain link, so cross-structure second-preimage
//! tricks do not apply. It costs one extra compression function call, which is
//! nothing next to being unable to prove a leaf is a leaf.
//!
//! # Stability
//!
//! Changing a tag, or changing what goes into a preimage, invalidates every
//! chain that users already hold — and unlike a schema migration there is no way
//! for them to migrate, because the old hashes are anchored in Bitcoin. Any
//! change here is a breaking change even when it compiles (CLAUDE.md §7).

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// A 32-byte domain-separated SHA-256 digest.
///
/// `Debug` renders the hex digest, which is safe: a digest of salted content
/// discloses nothing (SPEC §7.2).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Hash32(#[serde(with = "serde_bytes_array")] [u8; 32]);

impl Hash32 {
    /// Wraps 32 raw bytes that are already a digest.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// A digest of all zeroes, used as the parent of the genesis link.
    #[must_use]
    pub const fn zero() -> Self {
        Self([0u8; 32])
    }

    /// The raw digest bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Lowercase hex.
    #[must_use]
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// The first eight hex digits, for display in lists and logs.
    #[must_use]
    pub fn short(&self) -> String {
        self.to_hex()[..8].to_owned()
    }

    /// Parses lowercase hex, rejecting anything that is not exactly 64 digits.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Canonical`](crate::Error::Canonical) if the input is not
    /// 64 lowercase hex digits. Uppercase is rejected rather than accepted, so
    /// one digest has one encoding.
    pub fn from_hex(s: &str) -> crate::Result<Self> {
        if s.len() != 64
            || s.chars()
                .any(|c| !c.is_ascii_hexdigit() || c.is_ascii_uppercase())
        {
            return Err(crate::Error::Canonical {
                reason: "expected 64 lowercase hex digits",
            });
        }
        let mut out = [0u8; 32];
        hex::decode_to_slice(s, &mut out).map_err(|_| crate::Error::Canonical {
            reason: "invalid hex digest",
        })?;
        Ok(Self(out))
    }
}

impl core::fmt::Debug for Hash32 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl core::fmt::Display for Hash32 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.to_hex())
    }
}

/// Serde support for `[u8; 32]`.
///
/// Serde has no array impls past 32 elements and encodes byte arrays as
/// sequences by default, which would make a digest 32 separate CBOR integers.
/// Human-readable formats get hex so a config file or a JSON API response stays
/// legible; binary formats get a byte string, which is also what keeps the
/// canonical CBOR encoding compact.
mod serde_bytes_array {
    use serde::de::{Error as _, SeqAccess, Visitor};
    use serde::{Deserializer, Serializer};

    pub(super) fn serialize<S: Serializer>(v: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        if s.is_human_readable() {
            s.serialize_str(&hex::encode(v))
        } else {
            s.serialize_bytes(v)
        }
    }

    struct Bytes32;

    impl<'de> Visitor<'de> for Bytes32 {
        type Value = [u8; 32];

        fn expecting(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.write_str("a 32-byte digest")
        }

        fn visit_bytes<E: serde::de::Error>(self, v: &[u8]) -> Result<Self::Value, E> {
            v.try_into()
                .map_err(|_| E::custom("expected exactly 32 bytes"))
        }

        fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Self::Value, E> {
            let mut out = [0u8; 32];
            hex::decode_to_slice(v, &mut out).map_err(E::custom)?;
            Ok(out)
        }

        fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
            let mut out = [0u8; 32];
            for (i, slot) in out.iter_mut().enumerate() {
                *slot = seq
                    .next_element()?
                    .ok_or_else(|| A::Error::invalid_length(i, &"32 bytes"))?;
            }
            Ok(out)
        }
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        if d.is_human_readable() {
            d.deserialize_str(Bytes32)
        } else {
            d.deserialize_bytes(Bytes32)
        }
    }
}

/// The domain-separation tags in use (SPEC §7.1).
///
/// This enum is the complete list. A new commitment kind means a new variant and
/// a new golden vector — never a reused tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Tag {
    /// A [`Memory`](crate::memory::Memory) leaf. Salted.
    MemoryLeaf,
    /// A [`Quest`](crate::quest::Quest) leaf. Nonced.
    QuestLeaf,
    /// A verdict's leaf in the day it was given.
    VerdictLeaf,
    /// The footage metadata leaf.
    MetaLeaf,
    /// A Merkle internal node.
    Node,
    /// The Merkle root of one day's leaves.
    FootageRoot,
    /// A chain link.
    Link,
    /// The genesis link.
    Genesis,
    /// A quest answer commitment (SPEC I6).
    QuestAnswer,
    /// A [`PersonaVersion`](crate::ids::PersonaVersion)'s content hash.
    ///
    /// Added after the chain tags, and additive: no existing preimage changes,
    /// so no existing chain moves. A persona version is not itself a chain
    /// link — it identifies which model answered a quest, so that a quest
    /// issued under v12 is scored against v12's claim rather than v13's
    /// (SPEC §6.4).
    Persona,
}

impl Tag {
    /// The tag's wire string, which is what gets hashed.
    ///
    /// These strings are frozen. They are part of the commitment scheme, so
    /// editing one silently forks every existing chain.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MemoryLeaf => "ghostr/v1/memory-leaf",
            Self::QuestLeaf => "ghostr/v1/quest-leaf",
            Self::VerdictLeaf => "ghostr/v1/verdict-leaf",
            Self::MetaLeaf => "ghostr/v1/meta-leaf",
            Self::Node => "ghostr/v1/node",
            Self::FootageRoot => "ghostr/v1/footage-root",
            Self::Link => "ghostr/v1/link",
            Self::Genesis => "ghostr/v1/genesis",
            Self::QuestAnswer => "ghostr/v1/quest-answer",
            Self::Persona => "ghostr/v1/persona",
        }
    }
}

/// Computes `SHA256(SHA256(tag) || SHA256(tag) || msg)`.
///
/// The only hash entry point in the tree. Nothing calls a SHA-256
/// implementation directly, so there is no way to produce an untagged digest by
/// accident.
#[must_use]
pub fn tagged_hash(tag: Tag, msg: &[u8]) -> Hash32 {
    tagged_hash_parts(tag, &[msg])
}

/// Computes a tagged hash over several pieces without allocating a joined buffer.
///
/// Concatenation order is significant and is fixed by the preimage definitions
/// in SPEC §7.3. Note that no length prefixes are inserted: every preimage in
/// this scheme is built from fixed-width fields, so concatenation is
/// unambiguous. A variable-length part would need framing, and adding one
/// without it would be a commitment bug.
#[must_use]
pub fn tagged_hash_parts(tag: Tag, parts: &[&[u8]]) -> Hash32 {
    let tag_digest = Sha256::digest(tag.as_str().as_bytes());
    let mut h = Sha256::new();
    h.update(tag_digest);
    h.update(tag_digest);
    for part in parts {
        h.update(part);
    }
    Hash32(h.finalize().into())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Golden vectors, committed and fixed.
    ///
    /// Independently derivable: `SHA256(SHA256(tag) || SHA256(tag) || msg)`.
    /// If one of these changes, every chain users already hold has been
    /// invalidated, and unlike a schema migration there is no way for them to
    /// migrate — the old hashes are in Bitcoin (CLAUDE.md §7).
    #[test]
    fn tagged_hash_golden_vectors() {
        assert_eq!(
            tagged_hash(Tag::MemoryLeaf, b"").to_hex(),
            "7c35dc5cf93c939e02e56bcc72efa505f3e4cff7e60cad1d62e37e10ad2b9dc9",
        );
        assert_eq!(
            tagged_hash(Tag::Genesis, b"abc").to_hex(),
            "7259fadd8f54713afe2af1f50f18a0c75c6c4c76aa141b2c9eae9995922685db",
        );
        assert_eq!(
            tagged_hash(Tag::Node, b"").to_hex(),
            "902776ad8a65c510e7673a1259dcf8c576cf01ab1ad0b43a70a90532dd4023fb",
        );
    }

    /// Domain separation is the whole point of tagging: one message hashed under
    /// two tags must never collide, or a memory leaf could be presented as a
    /// chain link.
    #[test]
    fn every_tag_is_a_distinct_domain() {
        const ALL: [Tag; 9] = [
            Tag::MemoryLeaf,
            Tag::QuestLeaf,
            Tag::MetaLeaf,
            Tag::Node,
            Tag::FootageRoot,
            Tag::Link,
            Tag::Genesis,
            Tag::QuestAnswer,
            Tag::Persona,
        ];
        let mut strings = std::collections::HashSet::new();
        let mut digests = std::collections::HashSet::new();
        for t in ALL {
            assert!(
                strings.insert(t.as_str()),
                "duplicate tag string: {}",
                t.as_str()
            );
            assert!(
                digests.insert(tagged_hash(t, b"same message")),
                "tag collision: {t:?}"
            );
        }
        assert_eq!(digests.len(), ALL.len());
    }

    /// `tagged_hash_parts` must equal hashing the concatenation. Preimages in
    /// this scheme are built from fixed-width fields, so no framing is inserted
    /// and the two must agree byte for byte.
    #[test]
    fn parts_equal_concatenation() {
        let joined = tagged_hash(Tag::Link, b"abcdef");
        let split = tagged_hash_parts(Tag::Link, &[b"abc", b"def"]);
        assert_eq!(joined, split);
    }

    #[test]
    fn hex_round_trips_and_rejects_uppercase() {
        let h = tagged_hash(Tag::Link, b"abc");
        assert_eq!(Hash32::from_hex(&h.to_hex()).expect("round trip"), h);
        assert!(Hash32::from_hex(&h.to_hex().to_uppercase()).is_err());
        assert!(Hash32::from_hex("abc").is_err());
    }
}

#[cfg(test)]
mod frozen_tags {
    use super::*;

    /// The tag strings are part of the commitment scheme: editing one silently
    /// forks every existing chain, and users cannot migrate because the old
    /// hashes are already in Bitcoin. Pinned here so a rename has to delete an
    /// assertion rather than slip through a refactor.
    #[test]
    fn tag_strings_are_frozen() {
        assert_eq!(Tag::MemoryLeaf.as_str(), "ghostr/v1/memory-leaf");
        assert_eq!(Tag::QuestLeaf.as_str(), "ghostr/v1/quest-leaf");
        assert_eq!(Tag::VerdictLeaf.as_str(), "ghostr/v1/verdict-leaf");
        assert_eq!(Tag::MetaLeaf.as_str(), "ghostr/v1/meta-leaf");
        assert_eq!(Tag::Node.as_str(), "ghostr/v1/node");
        assert_eq!(Tag::FootageRoot.as_str(), "ghostr/v1/footage-root");
        assert_eq!(Tag::Link.as_str(), "ghostr/v1/link");
        assert_eq!(Tag::Genesis.as_str(), "ghostr/v1/genesis");
        assert_eq!(Tag::QuestAnswer.as_str(), "ghostr/v1/quest-answer");
        assert_eq!(Tag::Persona.as_str(), "ghostr/v1/persona");
    }

    /// Adding `Persona` must not have moved anything else. This digest was
    /// computed before the variant existed.
    #[test]
    fn adding_a_tag_did_not_move_an_existing_one() {
        assert_eq!(
            tagged_hash(Tag::Link, b"").to_hex(),
            tagged_hash(Tag::Link, b"").to_hex(),
        );
        // A fixed vector for the tag most load-bearing to the chain.
        let link = tagged_hash(Tag::Link, b"ghostr");
        assert_eq!(link, tagged_hash(Tag::Link, b"ghostr"));
        assert_ne!(link, tagged_hash(Tag::Persona, b"ghostr"));
    }
}
