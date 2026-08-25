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

/// A 32-byte domain-separated SHA-256 digest.
///
/// `Debug` renders the hex digest, which is safe: a digest of salted content
/// discloses nothing (SPEC §7.2).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Hash32([u8; 32]);

impl Hash32 {
    /// Wraps 32 raw bytes that are already a digest.
    #[must_use]
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// The raw digest bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Lowercase hex.
    #[must_use]
    pub fn to_hex(&self) -> String {
        todo!("lowercase hex-encode the digest")
    }

    /// Parses lowercase hex, rejecting anything that is not exactly 64 digits.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Canonical`](crate::Error::Canonical) if the input is not
    /// 64 lowercase hex digits. Uppercase is rejected rather than accepted, so
    /// one digest has one encoding.
    pub fn from_hex(s: &str) -> crate::Result<Self> {
        todo!("parse exactly 64 lowercase hex digits")
    }
}

impl core::fmt::Debug for Hash32 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        todo!("write the lowercase hex digest")
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
}

impl Tag {
    /// The tag's wire string, which is what gets hashed.
    ///
    /// These strings are frozen. They are part of the commitment scheme, so
    /// editing one silently forks every existing chain.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MemoryLeaf => "ghostr/v1/memory-leaf",
            Self::QuestLeaf => "ghostr/v1/quest-leaf",
            Self::MetaLeaf => "ghostr/v1/meta-leaf",
            Self::Node => "ghostr/v1/node",
            Self::FootageRoot => "ghostr/v1/footage-root",
            Self::Link => "ghostr/v1/link",
            Self::Genesis => "ghostr/v1/genesis",
            Self::QuestAnswer => "ghostr/v1/quest-answer",
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
    todo!("SHA256(SHA256(tag) || SHA256(tag) || msg)")
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
    todo!("SHA256(SHA256(tag) || SHA256(tag) || parts.concat())")
}
