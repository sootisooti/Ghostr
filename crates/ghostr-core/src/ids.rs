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
                Self($crate::ids::uuid_v7(unix_millis, random))
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
                format!("{}:{}", $prefix, &self.0.as_simple().to_string()[..8])
            }

            #[doc = concat!("Parses a `", $prefix, ":`-prefixed short form or a full UUID.")]
            ///
            /// # Errors
            ///
            /// Returns [`Error::Canonical`](crate::Error::Canonical) if the
            /// input is neither.
            pub fn parse(s: &str) -> $crate::Result<Self> {
                let body = s.strip_prefix(concat!($prefix, ":")).unwrap_or(s);
                Uuid::parse_str(body)
                    .map(Self)
                    .map_err(|_| $crate::Error::Canonical { reason: "not a valid identifier" })
            }
        }

        impl core::fmt::Display for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                write!(f, "{}:{}", $prefix, self.0.as_simple())
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
        Self(uuid_v7(unix_millis, random))
    }

    /// Parses a chain identifier.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Canonical`](crate::Error::Canonical) if the input is not
    /// a UUID.
    pub fn parse(s: &str) -> crate::Result<Self> {
        Uuid::parse_str(s)
            .map(Self)
            .map_err(|_| crate::Error::Canonical {
                reason: "not a valid chain id",
            })
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
    /// The version in force before any distillation has run.
    ///
    /// M0 has no persona model, but footage still records which ghost sealed it,
    /// so ordinal 0 with a zero content hash means "no persona yet" rather than
    /// leaving the field optional and pushing the case onto every reader.
    #[must_use]
    pub const fn genesis() -> Self {
        Self {
            ordinal: 0,
            content: crate::hash::Hash32::zero(),
        }
    }

    /// Renders as `v12@a1b2c3d4`, the form used in CLI output.
    #[must_use]
    pub fn display_short(&self) -> String {
        format!("v{}@{}", self.ordinal, self.content.short())
    }
}

/// Builds a UUIDv7 from an explicit timestamp and 10 bytes of entropy.
///
/// Written out rather than taken from `uuid`'s `v7` feature, which pulls
/// `getrandom` and would put an OS entropy source inside this crate. Layout per
/// RFC 9562 §5.7: 48-bit big-endian millisecond timestamp, 4-bit version,
/// 12 bits of entropy, 2-bit variant, 62 bits of entropy.
#[must_use]
pub(crate) fn uuid_v7(unix_millis: u64, random: [u8; 10]) -> Uuid {
    let mut bytes = [0u8; 16];
    bytes[..6].copy_from_slice(&unix_millis.to_be_bytes()[2..]);
    bytes[6] = 0x70 | (random[0] & 0x0f);
    bytes[7] = random[1];
    bytes[8] = 0x80 | (random[2] & 0x3f);
    bytes[9..].copy_from_slice(&random[3..]);
    Uuid::from_bytes(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uuid_v7_sets_version_and_variant() {
        let u = uuid_v7(0x0192_3f4d_5e6a, [0xff; 10]);
        assert_eq!(u.get_version_num(), 7);
        // RFC 4122 variant: top two bits of octet 8 are 0b10.
        assert_eq!(u.as_bytes()[8] & 0xc0, 0x80);
    }

    #[test]
    fn uuid_v7_is_time_ordered() {
        // Sortability is why v7 was chosen: ids allocated later sort later, so
        // an ordered scan of the store is an ordered scan of history.
        let early = MemoryId::new(1_000, [0x00; 10]);
        let late = MemoryId::new(2_000, [0x00; 10]);
        assert!(early < late);
    }

    #[test]
    fn ids_round_trip_through_their_display_form() {
        let id = MemoryId::new(1_700_000_000_000, [7u8; 10]);
        assert_eq!(MemoryId::parse(&id.to_string()).expect("round trip"), id);
        assert!(MemoryId::parse("not-an-id").is_err());
    }

    #[test]
    fn display_short_is_prefixed() {
        let id = SourceId::new(1, [0u8; 10]);
        assert!(id.display_short().starts_with("src:"));
    }
}
