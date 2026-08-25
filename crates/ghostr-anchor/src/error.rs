//! This crate's error type.

/// Result alias for this crate.
pub type Result<T, E = Error> = core::result::Result<T, E>;

/// Something went wrong building, anchoring, or verifying the chain.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// A recomputed link did not match the stored one.
    ///
    /// Names the first bad `seq`, which is the only useful thing to say: every
    /// link after it will also mismatch, and reporting them all buries the one
    /// that matters.
    #[error("chain broken at seq {seq}")]
    ChainBroken {
        /// The first sequence whose link did not verify.
        seq: u64,
    },

    /// The chain skips a sequence number (SPEC I3).
    #[error("chain gap between seq {previous} and {next}")]
    ChainGap {
        /// Last good sequence.
        previous: u64,
        /// Next sequence found.
        next: u64,
    },

    /// A Merkle inclusion proof did not verify.
    #[error("inclusion proof does not verify against root")]
    InclusionFailed,

    /// A calendar could not be reached.
    ///
    /// Not fatal to sealing. The seal already happened; this only delays the
    /// attestation, and the upgrade queue will retry.
    #[error("calendar unreachable: {calendar}")]
    CalendarUnreachable {
        /// Which calendar.
        calendar: String,
    },

    /// The proof is still pending and cannot be verified yet.
    ///
    /// The expected state for hours after sealing, not an error condition in the
    /// ordinary sense.
    #[error("proof is still pending confirmation")]
    ProofPending,

    /// A `.ots` proof was malformed.
    #[error("OpenTimestamps proof is malformed")]
    MalformedProof,

    /// The proof's digest is not the one that was submitted.
    ///
    /// A calendar returning a proof for a different digest is either broken or
    /// hostile, and either way the proof is worthless.
    #[error("proof commits to a different digest than the one submitted")]
    ProofDigestMismatch,

    /// No block header source was configured.
    ///
    /// Verification cannot be faked. Without headers, `gst verify` reports that
    /// it could not check the anchor rather than implying it did.
    #[error("no block header source is configured")]
    NoHeaderSource,

    /// The attested block does not exist or does not match.
    #[error("block at height {height} does not match the proof")]
    BlockMismatch {
        /// Which height.
        height: u32,
    },

    /// A hashing or serialization step failed.
    #[error("core error")]
    Core(#[from] ghostr_core::Error),
}
