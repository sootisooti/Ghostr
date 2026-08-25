//! This crate's error type.

/// Result alias for this crate.
pub type Result<T, E = Error> = core::result::Result<T, E>;

/// Something went wrong distilling or querying the persona.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// There is not enough corpus to distil a persona yet.
    ///
    /// A real, expected state for a new user, not a failure. A ghost built from
    /// four notes would be confident and wrong, which is worse than absent.
    #[error("insufficient corpus: {have} memories, need {need}")]
    InsufficientCorpus {
        /// How many memories exist.
        have: u32,
        /// How many are needed.
        need: u32,
    },

    /// A delta from a held-out quest reached distillation (SPEC I7).
    ///
    /// A bug, and a serious one: it means the fidelity score is being computed
    /// on data the model trained on. Fails loudly rather than being filtered
    /// out silently, because a silent filter hides the upstream defect.
    #[error("held-out correction reached distillation; refusing")]
    HoldoutLeak,

    /// A facet claim carried no evidence.
    ///
    /// Every claim must trace to at least one memory. One that does not is a
    /// hallucination, and admitting it would break the audit trail the symbolic
    /// model exists to provide.
    #[error("persona claim has no supporting evidence")]
    UnsupportedClaim,

    /// A facet value could not be encoded canonically.
    ///
    /// A bug rather than a user state: every ratio in a persona is clamped
    /// where it is computed, so reaching here means one escaped its range and
    /// the version hash cannot be formed.
    #[error("persona facet is not canonically encodable")]
    Canonical(#[from] ghostr_core::Error),

    /// The model failed or returned unusable output.
    #[error("model error")]
    Llm(#[from] ghostr_llm::Error),

    /// The store failed.
    #[error("store error")]
    Store(#[from] ghostr_store::Error),
}
