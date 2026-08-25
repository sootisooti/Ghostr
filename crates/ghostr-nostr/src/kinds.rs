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

    /// The `d` tag for one instance of this kind.
    #[must_use]
    pub fn d_tag(self, identifier: &str) -> String {
        todo!("format as `ghostr/v1/<type>/<identifier>`")
    }
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
