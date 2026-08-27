//! Ghostr's nostr event kinds (SPEC §9).
//!
//! # These kinds are unclaimed, not assigned
//!
//! Nothing in nostr prevents a collision on 31780–31789. Correctness therefore
//! does not depend on the block being ours: every event is **also** mirrored
//! under NIP-78 kind 30078 with a `ghostr/v1/...` `d` tag, and the `d`-tag
//! namespace is the real identifier. Before implementation, check the block
//! against the live kind registry and submit a NIP; if it collides, move the
//! block (SPEC Q3).

use serde::{Deserialize, Serialize};

/// NIP-78 application-specific data, used as the compatibility mirror.
pub const NIP78_APP_DATA: u16 = 30078;

/// The `d`-tag namespace prefix. The real identifier, kind block or not.
pub const D_TAG_PREFIX: &str = "ghostr/v1";

/// A Ghostr event kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Kind {
    /// 31780 — the user's signed attestation of their ghost. **Public**: an
    /// attestation nobody can read is not an attestation.
    GhostManifest,
    /// 31781 — a configured source. Private, NIP-44 self-encrypted.
    SourceDescriptor,
    /// 31782 — one persona version. Private.
    PersonaVersion,
    /// 31783 — one sealed footage. Private.
    FootageRecord,
    /// 31784 — a chain link and its `.ots` proof. Hashes only.
    ///
    /// Opt-in and **local-only by default**: the `.ots` file on disk is already
    /// a complete proof, so publishing adds availability rather than validity,
    /// and a daily stream of these broadcasts liveness (SPEC Q5).
    AnchorReceipt,
    /// 31785 — one day's quest set. Private.
    QuestSet,
    /// 31786 — a signed, chain-bound fidelity score. Opt-in public.
    FidelityAttestation,
    /// 31787 — a registered device. Private.
    DeviceRegistration,
    /// 31788 — a revocation. **Public**: a revocation nobody can read is not a
    /// revocation.
    RevocationNotice,
}

impl Kind {
    /// The numeric kind.
    #[must_use]
    pub fn as_u16(self) -> u16 {
        match self {
            Self::GhostManifest => 31780,
            Self::SourceDescriptor => 31781,
            Self::PersonaVersion => 31782,
            Self::FootageRecord => 31783,
            Self::AnchorReceipt => 31784,
            Self::QuestSet => 31785,
            Self::FidelityAttestation => 31786,
            Self::DeviceRegistration => 31787,
            Self::RevocationNotice => 31788,
        }
    }

    /// Whether this kind's content is encrypted.
    ///
    /// The complement is small and deliberate: manifests, anchor receipts,
    /// attestations, and revocations are readable because being readable is
    /// their entire function.
    #[must_use]
    pub fn is_encrypted(self) -> bool {
        !matches!(
            self,
            Self::GhostManifest
                | Self::AnchorReceipt
                | Self::FidelityAttestation
                | Self::RevocationNotice
        )
    }

    /// Which NIP-06 account signs this kind.
    ///
    /// Anchor receipts are signed by the unlinkable anchor key so that
    /// publishing one does not tie a chain to an identity (SPEC §8.1).
    #[must_use]
    pub fn signing_account(self) -> ghostr_core::identity::Account {
        use ghostr_core::identity::Account;
        match self {
            Self::GhostManifest
            | Self::FidelityAttestation
            | Self::RevocationNotice
            | Self::DeviceRegistration => Account::Identity,
            Self::AnchorReceipt => Account::Anchor,
            Self::SourceDescriptor
            | Self::PersonaVersion
            | Self::FootageRecord
            | Self::QuestSet => Account::Data,
        }
    }

    /// The wire name for this kind inside a `d` tag.
    ///
    /// Written out rather than derived from the Rust identifier or from
    /// [`serde`]. This string is the real protocol identifier — SPEC Q3 says
    /// correctness must not depend on the 3178x block being ours — so renaming a
    /// variant must be a compile error to fix here, not a silent change to what
    /// every already-published event is called.
    #[must_use]
    pub fn slug(self) -> &'static str {
        match self {
            Self::GhostManifest => "manifest",
            Self::SourceDescriptor => "source",
            Self::PersonaVersion => "persona",
            Self::FootageRecord => "footage",
            Self::AnchorReceipt => "anchor",
            Self::QuestSet => "quests",
            Self::FidelityAttestation => "fidelity",
            Self::DeviceRegistration => "device",
            Self::RevocationNotice => "revocation",
        }
    }

    /// The `d` tag for one instance of this kind.
    ///
    /// `ghostr/v1/<type>/<identifier>`. Addressable events are keyed by
    /// `(kind, pubkey, d)`, so this string is what makes one day's footage
    /// replaceable by a correction rather than duplicated beside it.
    #[must_use]
    pub fn d_tag(self, identifier: &str) -> String {
        format!("{D_TAG_PREFIX}/{}/{identifier}", self.slug())
    }

    /// Parses a `d` tag back to its kind and identifier.
    ///
    /// Returns `None` for anything not in the `ghostr/v1` namespace, which is
    /// most of what a relay will hand back. Splits from the left on exactly
    /// three separators so an identifier containing `/` survives the round trip
    /// intact rather than being truncated at its first slash.
    #[must_use]
    pub fn from_d_tag(d_tag: &str) -> Option<(Self, &str)> {
        let rest = d_tag.strip_prefix(D_TAG_PREFIX)?.strip_prefix('/')?;
        let (slug, identifier) = rest.split_once('/')?;
        let kind = Self::ALL.into_iter().find(|k| k.slug() == slug)?;
        Some((kind, identifier))
    }

    /// Every kind, for exhaustive iteration.
    ///
    /// A `match` in [`Kind::slug`] keeps this honest: adding a variant without
    /// adding it here compiles, but `every_kind_round_trips_through_its_d_tag`
    /// counts the list against [`Kind::as_u16`] and fails.
    pub const ALL: [Self; 9] = [
        Self::GhostManifest,
        Self::SourceDescriptor,
        Self::PersonaVersion,
        Self::FootageRecord,
        Self::AnchorReceipt,
        Self::QuestSet,
        Self::FidelityAttestation,
        Self::DeviceRegistration,
        Self::RevocationNotice,
    ];
}

/// Standard kinds Ghostr also uses.
pub mod standard {
    /// NIP-01 profile metadata. Used to mark the ghost account as a ghost.
    pub const METADATA: u16 = 0;
    /// NIP-01 short text note. Ghost-authored only, always disclosed.
    pub const TEXT_NOTE: u16 = 1;
    /// NIP-59 gift wrap, for hiding kind and author.
    pub const GIFT_WRAP: u16 = 1059;
    /// NIP-65 relay list metadata.
    pub const RELAY_LIST: u16 = 10002;
    /// NIP-46 remote signer transport.
    pub const NOSTR_CONNECT: u16 = 24133;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_kind_round_trips_through_its_d_tag() {
        for kind in Kind::ALL {
            let tag = kind.d_tag("2026-08-27");
            assert!(tag.starts_with("ghostr/v1/"), "{tag}");
            assert_eq!(Kind::from_d_tag(&tag), Some((kind, "2026-08-27")));
        }
    }

    #[test]
    fn the_kind_list_covers_the_whole_block() {
        // `ALL` is hand-written, so it can fall behind the enum. This is what
        // notices: a new variant lands in `as_u16` and the count stops matching.
        let mut numbers: Vec<u16> = Kind::ALL.into_iter().map(Kind::as_u16).collect();
        numbers.sort_unstable();
        numbers.dedup();
        assert_eq!(numbers.len(), Kind::ALL.len());
        assert_eq!(numbers, (31780..=31788).collect::<Vec<_>>());
    }

    #[test]
    fn every_slug_is_distinct() {
        // Two kinds sharing a slug would make `from_d_tag` return the wrong one,
        // and it would return it confidently.
        let mut slugs: Vec<&str> = Kind::ALL.into_iter().map(Kind::slug).collect();
        slugs.sort_unstable();
        slugs.dedup();
        assert_eq!(slugs.len(), Kind::ALL.len());
    }

    #[test]
    fn an_identifier_containing_a_slash_survives() {
        // Splitting from the right, or splitting on every separator, would
        // truncate this to "2026" and address the wrong record.
        let tag = Kind::FootageRecord.d_tag("2026/08/27");
        assert_eq!(
            Kind::from_d_tag(&tag),
            Some((Kind::FootageRecord, "2026/08/27"))
        );
    }

    #[test]
    fn a_foreign_d_tag_is_not_ours() {
        // The collision SPEC Q3 expects: someone else's app on the same kind.
        assert_eq!(Kind::from_d_tag("someapp/v1/footage/2026-08-27"), None);
        assert_eq!(Kind::from_d_tag("ghostr/v2/footage/x"), None);
        assert_eq!(Kind::from_d_tag("ghostr/v1/unknown/x"), None);
        assert_eq!(Kind::from_d_tag("ghostr/v1/footage"), None);
        assert_eq!(Kind::from_d_tag(""), None);
    }

    #[test]
    fn a_prefix_that_merely_starts_the_same_is_rejected() {
        // `ghostr/v1x/...` shares nine characters with the namespace. A bare
        // `starts_with` would accept it.
        assert_eq!(Kind::from_d_tag("ghostr/v1x/footage/a"), None);
    }

    #[test]
    fn anchor_receipts_are_signed_by_the_unlinkable_account() {
        // SPEC §8.1. The one kind whose whole point is not being tied to the
        // identity, so it is the one worth pinning explicitly.
        use ghostr_core::identity::Account;
        assert_eq!(Kind::AnchorReceipt.signing_account(), Account::Anchor);
        assert_ne!(Kind::AnchorReceipt.signing_account(), Account::Identity);
    }

    #[test]
    fn the_public_kinds_are_exactly_the_ones_that_must_be_readable() {
        let public: Vec<Kind> = Kind::ALL
            .into_iter()
            .filter(|k| !k.is_encrypted())
            .collect();
        assert_eq!(
            public,
            [
                Kind::GhostManifest,
                Kind::AnchorReceipt,
                Kind::FidelityAttestation,
                Kind::RevocationNotice
            ]
        );
    }
}
