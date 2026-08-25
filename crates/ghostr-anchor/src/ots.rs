//! OpenTimestamps submission and proof upgrading (SPEC §7.4).
//!
//! # Why OTS rather than an OP_RETURN per day
//!
//! Calendars aggregate thousands of digests into one transaction, so the
//! marginal cost of a daily anchor is zero: no wallet, no UTXO management, no
//! fee estimation in the sealing path. The trade is a dependency on calendar
//! availability and a timestamp granularity of hours rather than minutes.
//! Neither matters for a daily journal.
//!
//! # Why anchor daily when the tip suffices
//!
//! Anchoring `link_n` transitively timestamps every earlier link, so daily
//! anchoring is belt and braces. It bounds how much history is exposed if a run
//! of anchors fails, and it gives every day an independently checkable proof
//! rather than requiring a walk to the tip.

use async_trait::async_trait;
use ghostr_core::hash::Hash32;
use ghostr_core::time::Timestamp;
use serde::{Deserialize, Serialize};

/// Submits digests for timestamping and upgrades the resulting proofs.
#[async_trait]
pub trait Anchorer: Send + Sync {
    /// Submits a digest to the configured calendars.
    ///
    /// Submits to at least two independent calendars. One calendar is a single
    /// point of failure for a proof the user may need years later, and the cost
    /// of a second is a second HTTP request.
    ///
    /// # Errors
    ///
    /// Returns [`Error::CalendarUnreachable`](crate::Error::CalendarUnreachable)
    /// only if *every* calendar failed. A partial success is a success.
    async fn submit(&self, digest: Hash32) -> crate::Result<PendingProof>;

    /// Attempts to upgrade a pending proof to a confirmed one.
    ///
    /// Called on a retry schedule: hourly for 24 hours, then daily for a week.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ProofPending`](crate::Error::ProofPending) if the
    /// calendar has not yet published — the expected outcome for the first few
    /// hours, and not a failure.
    async fn upgrade(&self, pending: &PendingProof) -> crate::Result<AnchorState>;

    /// Verifies a complete proof against Bitcoin.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NoHeaderSource`](crate::Error::NoHeaderSource) if no
    /// header source is configured — never a silent pass.
    async fn verify(
        &self,
        proof: &Proof,
        headers: &dyn crate::verify::BlockHeaderSource,
    ) -> crate::Result<AnchorState>;
}

/// A submitted but unconfirmed timestamp.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingProof {
    /// The digest submitted.
    pub digest: Hash32,
    /// When it was submitted.
    pub submitted_at: Timestamp,
    /// Which calendars accepted it.
    pub calendars: Vec<String>,
    /// The serialized `.ots` bytes as they stand.
    pub ots_bytes: Vec<u8>,
    /// How many upgrade attempts have been made.
    pub attempts: u32,
}

/// A complete `.ots` proof with a Bitcoin attestation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Proof {
    /// The digest this proves.
    pub digest: Hash32,
    /// The serialized `.ots` bytes.
    pub ots_bytes: Vec<u8>,
    /// Block height of the attestation.
    pub block_height: u32,
}

/// Where a digest stands on its way into a block.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "state")]
#[non_exhaustive]
pub enum AnchorState {
    /// Not yet submitted.
    Unanchored,
    /// Submitted, awaiting a calendar's Bitcoin transaction.
    Pending(PendingProof),
    /// Confirmed in a block.
    Confirmed {
        /// Block height.
        block_height: u32,
        /// Block time — the upper bound the proof actually establishes.
        block_time: Timestamp,
        /// The complete proof.
        proof: Proof,
    },
    /// Repeated failures.
    ///
    /// Never blocks sealing. The chain link is valid without an attestation; the
    /// day simply lacks external evidence until this recovers.
    Failed {
        /// How many attempts were made.
        attempts: u32,
        /// The last error, in transport terms.
        last_error: String,
    },
}

impl AnchorState {
    /// Whether this state carries a Bitcoin attestation.
    #[must_use]
    pub fn is_confirmed(&self) -> bool {
        matches!(self, Self::Confirmed { .. })
    }
}

/// A calendar endpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CalendarConfig {
    /// Calendar URL.
    pub url: String,
    /// Whether this calendar is required for a submission to count.
    pub required: bool,
}

/// The default calendars.
///
/// Public, well-known, and independently operated. A user who does not want to
/// disclose an IP to them should route through Tor: the calendar sees a 32-byte
/// digest and an IP, which is a small leak but not a zero one
/// (THREAT_MODEL §T4).
#[must_use]
pub fn default_calendars() -> Vec<CalendarConfig> {
    todo!("return the default OpenTimestamps calendar list")
}
