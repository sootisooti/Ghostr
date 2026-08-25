//! Verification against Bitcoin, and honesty about what was actually checked.

use async_trait::async_trait;
use ghostr_core::time::Timestamp;
use serde::{Deserialize, Serialize};

/// Supplies Bitcoin block headers.
#[async_trait]
pub trait BlockHeaderSource: Send + Sync {
    /// The header at a height.
    ///
    /// # Errors
    ///
    /// Returns [`Error::BlockMismatch`](crate::Error::BlockMismatch) if the
    /// height is unknown.
    async fn header(&self, height: u32) -> crate::Result<BlockHeader>;

    /// How much this source can be trusted.
    ///
    /// Surfaced in `gst verify` output so it can say *"verified against a block
    /// explorer"* rather than implying a verification it did not perform. A
    /// verifier that overstates its own assurance is worse than one that
    /// declines to run.
    fn trust_level(&self) -> HeaderTrust;
}

/// A Bitcoin block header, reduced to what a proof needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockHeader {
    /// Height.
    pub height: u32,
    /// Merkle root of the block's transactions.
    pub merkle_root: [u8; 32],
    /// Block timestamp.
    pub time: Timestamp,
}

/// How much a header source can be trusted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum HeaderTrust {
    /// A full node the user runs. No trust required.
    FullNode,
    /// An Electrum server with SPV proofs. Trusts the server for chain selection.
    Electrum,
    /// A block explorer over HTTPS. Trusts the operator entirely.
    Explorer,
}

/// The outcome of a verification run.
///
/// Every check is reported separately with its own status, so a partial
/// verification is legible as partial. Collapsing this to one boolean would let
/// "chain is intact but no anchors were checked" read as a pass.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VerificationReport {
    /// Chain integrity, link by link.
    pub chain: CheckResult,
    /// Merkle inclusion for any revealed memories.
    pub inclusion: CheckResult,
    /// Bitcoin attestations.
    pub anchors: CheckResult,
    /// Manifest and attestation signatures.
    pub signatures: CheckResult,
    /// Recomputed fidelity score, if a held-out set was revealed.
    pub score: CheckResult,
    /// How much the header source was trusted, if anchors were checked.
    pub header_trust: Option<HeaderTrust>,
}

/// The status of one check.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "status")]
#[non_exhaustive]
pub enum CheckResult {
    /// Checked and correct.
    Pass {
        /// How many items were checked.
        checked: u32,
    },
    /// Checked and wrong.
    Fail {
        /// What was wrong.
        detail: String,
        /// Where, when it is a sequence.
        at_seq: Option<u64>,
    },
    /// Not checked.
    ///
    /// Distinct from `Pass` on purpose: "no anchors were available to check" and
    /// "every anchor verified" must never render the same way.
    Skipped {
        /// Why it could not run.
        reason: String,
    },
}

impl CheckResult {
    /// Whether this check ran and passed.
    ///
    /// A skipped check is not a pass.
    #[must_use]
    pub fn passed(&self) -> bool {
        matches!(self, Self::Pass { .. })
    }
}
