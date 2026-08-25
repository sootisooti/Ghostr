//! The payloads carried by Ghostr's event kinds.
//!
//! Three of these are public documents that third parties are meant to read and
//! check: [`GhostManifest`], [`FidelityAttestation`], and [`RevocationNotice`].
//! They are the entire externally visible surface of the product's claim, so
//! their shapes are part of the protocol rather than an implementation detail.

use chrono::NaiveDate;
use ghostr_core::hash::Hash32;
use ghostr_core::identity::{GhostStatus, PublicKey};
use ghostr_core::ids::{ChainId, PersonaVersion};
use ghostr_core::time::Timestamp;
use serde::{Deserialize, Serialize};

/// Kind 31780. The user's signed attestation of their ghost.
///
/// The document that makes "provably his ghost" checkable: fetch it, verify the
/// identity key's signature, and you know which pubkey the user vouches for.
/// Public, and necessarily so.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GhostManifest {
    /// Which chain this ghost belongs to.
    pub chain_id: ChainId,
    /// The ghost's public key.
    pub ghost_pubkey: PublicKey,
    /// When the ghost was created.
    pub created_at: Timestamp,
    /// Current persona version ordinal. Content hash omitted — publishing it
    /// would let an observer detect when the persona changed.
    pub persona_ordinal: u32,
    /// The genesis link, which pins which chain this attests to.
    pub genesis_link: Hash32,
    /// Commitment scheme version, so a verifier knows which rules to apply.
    pub chain_version: u16,
    /// Whether the ghost is live.
    pub status: GhostStatus,
    /// What the ghost is permitted to do.
    pub policy: GhostPolicy,
    /// Which device is allowed to seal (SPEC Q10).
    ///
    /// Named here so a fork is detectable by a third party: two devices sealing
    /// the same chain would produce links that disagree with the manifest.
    pub sealing_device: String,
}

/// What a ghost is permitted to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct GhostPolicy {
    /// Whether the ghost may publish kind-1 notes. Off by default.
    pub may_publish_notes: bool,
    /// Whether the ghost may reply to others. Off by default.
    pub may_reply: bool,
    /// Whether fidelity attestations are published.
    pub publishes_fidelity: bool,
}

impl Default for GhostPolicy {
    /// Everything off.
    ///
    /// A ghost that can speak the moment it is created is a ghost that speaks
    /// before anyone has checked whether it sounds right.
    fn default() -> Self {
        Self {
            may_publish_notes: false,
            may_reply: false,
            publishes_fidelity: false,
        }
    }
}

/// Kind 31784. A chain link and its Bitcoin proof.
///
/// Contains a hash and a proof, no content. Signed by the anchor key so that
/// publishing it does not link the chain to an identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnchorReceipt {
    /// Which chain, as an opaque identifier rather than a pubkey.
    pub chain_id: ChainId,
    /// Sequence number.
    pub seq: u64,
    /// The link hash.
    pub link: Hash32,
    /// Base64 `.ots` proof.
    pub ots_base64: String,
    /// Attested block height, once confirmed.
    pub block_height: Option<u32>,
}

/// Kind 31786. A signed, chain-bound fidelity score (SPEC §9.4).
///
/// Says: *here is my ghost's score, and here is the Bitcoin-anchored commitment
/// to the quest record it was computed from.* A verifier checks the signature,
/// checks the proof, and — if the user reveals the held-out set — recomputes the
/// score independently.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FidelityAttestation {
    /// Which chain.
    pub chain_id: ChainId,
    /// The day this covers.
    pub as_of: NaiveDate,
    /// Which window, e.g. `rolling_90`.
    pub window: String,
    /// Weighted agreement.
    pub overall: f32,
    /// Held-out, non-decoy, non-void quests scored.
    pub sample_size: u32,
    /// Wilson interval at 95%.
    pub ci: (f32, f32),
    /// Expected calibration error.
    pub ece: f32,
    /// Decoy confirm rate.
    ///
    /// Published *inside* the attestation, not alongside it. A reader must not
    /// be able to receive the score without the number that discounts it
    /// (SPEC §4.4).
    pub decoy_confirm_rate: f32,
    /// Whether every convergence criterion was met.
    ///
    /// A score below the thresholds still publishes, flagged. Suppressing
    /// unconverged scores would make the published ones look like a milestone
    /// rather than a measurement.
    pub converged: bool,
    /// Chain `seq` this was computed at.
    pub committed_at_seq: u64,
    /// The link at that sequence.
    pub link: Hash32,
    /// Base64 `.ots` proof for that link.
    pub ots_base64: String,
}

/// Kind 31788. A revocation.
///
/// Plaintext and public. A revocation only works if everyone can read it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevocationNotice {
    /// What is being revoked.
    pub target: RevocationTarget,
    /// The revoked key.
    pub pubkey: PublicKey,
    /// When.
    pub revoked_at: Timestamp,
    /// Why, in the user's words.
    pub reason: String,
    /// The replacement, if there is one.
    pub replacement: Option<PublicKey>,
}

/// What a [`RevocationNotice`] revokes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum RevocationTarget {
    /// A ghost key. Recoverable in minutes: derive a new one and republish.
    GhostKey,
    /// A device registration.
    Device,
    /// The identity key itself.
    ///
    /// Damage control, not recovery. The seed is not rotatable, and anything
    /// already anchored stays frozen — an attacker with the seed writes a new
    /// future, never a new past (THREAT_MODEL §T5).
    IdentityKey,
}

/// Kind 31787. A device that participates in a chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceRegistration {
    /// Stable device identifier.
    pub device_id: String,
    /// Human-readable label.
    pub label: String,
    /// What this device may do.
    pub role: DeviceRole,
    /// When registered.
    pub registered_at: Timestamp,
}

/// What a device is allowed to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum DeviceRole {
    /// The one device that runs Memoria and advances `seq`.
    ///
    /// Exactly one per chain. Handover is an explicit signed manifest update;
    /// automatic election is tempting and wrong, because partition plus election
    /// equals fork (SPEC Q10).
    Sealer,
    /// Ingests and answers quests, but never seals.
    Replica,
}

/// The persona version an event was produced under, for private payloads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PayloadProvenance {
    /// Which persona version.
    pub persona_version: PersonaVersion,
    /// Which device wrote it.
    pub device_id_hash: Hash32,
}
