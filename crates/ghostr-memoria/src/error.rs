//! This crate's error type.

/// Result alias for this crate.
pub type Result<T, E = Error> = core::result::Result<T, E>;

/// Something went wrong compiling or sealing a day.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// A draft failed validation and cannot be sealed.
    ///
    /// Names the rules it broke. A count alone tells a user that something is
    /// wrong and gives them nowhere to go, and every one of these is either a
    /// bug in the pipeline or a shape of corpus nobody anticipated — both worth
    /// reading.
    ///
    /// The rule names carry field names and indices, never content (I8).
    #[error("draft failed validation: {}", broken.join("; "))]
    ValidationFailed {
        /// How many rules were broken.
        count: usize,
        /// Which rules, rendered.
        broken: Vec<String>,
    },

    /// The window to seal is already sealed.
    ///
    /// Expected on a restart after a crash between sealing and reporting, and
    /// treated as success by the scheduler rather than retried.
    #[error("seq {seq} is already sealed")]
    AlreadySealed {
        /// The sequence.
        seq: u64,
    },

    /// Sealing was attempted on a device that is not the sealer (SPEC Q10).
    #[error("this device is a replica and may not seal")]
    NotSealer,

    /// The extractor failed repeatedly on a cluster.
    ///
    /// Not fatal to the day. The cluster is marked unresolved and the seal
    /// proceeds: a day that refuses to close because one paragraph would not
    /// parse would leave a gap in the chain.
    #[error("extraction failed for {failed} of {total} clusters")]
    ExtractionIncomplete {
        /// Clusters that failed.
        failed: usize,
        /// Clusters attempted.
        total: usize,
    },

    /// The model failed.
    ///
    /// Only reachable with the `llm` feature. M0 has no model path at all.
    #[cfg(feature = "llm")]
    #[error("model error")]
    Llm(#[from] ghostr_llm::Error),

    /// The store failed.
    #[error("store error")]
    Store(#[from] ghostr_store::Error),

    /// Hashing or canonical encoding failed.
    #[error("core error")]
    Core(#[from] ghostr_core::Error),
}
