//! Newtype identifiers.
//!
//! CLAUDE.md §5: newtypes over primitives. A bare `Uuid` in a signature is a
//! chance to pass a `SourceId` where a `MemoryId` belongs; a bare `[u8; 32]` is
//! a chance to hash a quest leaf as a memory leaf. Both are silent at runtime
//! and loud in the commitment chain, which is the worst place to find them.
//!
//! Identifiers are UUIDv7 — time-ordered, sortable, and allocated without
//! coordination — except where a value is content-addressed.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Declares an opaque UUIDv7 newtype with a uniform surface.
macro_rules! uuid_id {
    ($(#[$meta:meta])* $name:ident, $prefix:literal) => {
        $(#[$meta])*
        #[derive(
            Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
        )]
        #[serde(transparent)]
        pub struct $name(Uuid);

        impl $name {
            #[doc = concat!("Allocates a fresh `", stringify!($name), "`.")]
            ///
            /// Takes the timestamp and entropy as arguments rather than reading
            /// them from the OS, so identifier allocation stays deterministic
            /// under test: time enters through [`Clock`](crate::time::Clock) and
            /// entropy through [`Rng`](crate::time::Rng) (ARCHITECTURE §4.7).
            #[must_use]
            pub fn new(unix_millis: u64, random: [u8; 10]) -> Self {
                todo!("build a UUIDv7 from the supplied timestamp and entropy")
            }

            /// Returns the wrapped UUID.
            #[must_use]
            pub fn as_uuid(&self) -> &Uuid {
                &self.0
            }

            #[doc = concat!("Renders as `", $prefix, ":` plus the first eight hex digits.")]
            ///
            /// Logging an identifier is always acceptable; logging the record it
            /// points at is not (SPEC I8).
            #[must_use]
            pub fn display_short(&self) -> String {
                todo!(concat!("render as `", $prefix, ":` plus eight hex digits"))
            }
        }
    };
}

uuid_id!(
    /// Identifies a [`Memory`](crate::memory::Memory).
    MemoryId,
    "mem"
);
uuid_id!(
    /// Identifies a [`Source`](crate::source::Source).
    SourceId,
    "src"
);
uuid_id!(
    /// Identifies a [`Quest`](crate::quest::Quest).
    QuestId,
    "qst"
);
uuid_id!(
    /// Identifies a person, place, or project referenced by a memory.
    ///
    /// The real name behind an `EntityId` lives in the encrypted entity table and
    /// never reaches a remote model: the egress boundary substitutes a stable
    /// pseudonym instead (SPEC §11.2).
    EntityId,
    "ent"
);
uuid_id!(
    /// Identifies a [`Thread`](crate::footage::Thread) — an open loop.
    ///
    /// Stable across days. This is what lets a thread opened on day 40 be
    /// recognised as closed on day 47 rather than read as two unrelated notes.
    ThreadId,
    "thr"
);
uuid_id!(
    /// Identifies a stored embedding in the local vector index.
    VectorId,
    "vec"
);

/// Identifies one commitment chain.
///
/// A chain belongs to exactly one identity and has exactly one sealing device
/// (SPEC Q10). It appears in the genesis link preimage so that two chains for
/// the same identity cannot produce colliding links.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ChainId(Uuid);

impl ChainId {
    /// Allocates a fresh chain identifier.
    #[must_use]
    pub fn new(unix_millis: u64, random: [u8; 10]) -> Self {
        todo!("build a UUIDv7 from the supplied timestamp and entropy")
    }

    /// Returns the wrapped UUID.
    #[must_use]
    pub fn as_uuid(&self) -> &Uuid {
        &self.0
    }
}

/// Identifies one version of the persona model.
///
/// Carries both a monotonic counter and the content hash of the facets, so
/// versions are *ordered* — which quest was issued under which ghost — and
/// *content-addressed*, so two distillations that produce identical facets are
/// recognisably the same model.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct PersonaVersion {
    /// Monotonic, starting at 1.
    pub ordinal: u32,
    /// Content hash of the [`Facets`](crate::persona::Facets) at this version.
    pub content: crate::hash::Hash32,
}

impl PersonaVersion {
    /// Renders as `v12@a1b2c3d4`, the form used in CLI output.
    #[must_use]
    pub fn display_short(&self) -> String {
        todo!("render as the ordinal, an at-sign, and eight hex digits of the content hash")
    }
}
