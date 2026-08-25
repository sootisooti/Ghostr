//! This crate's error type.
//!
//! Wraps every layer's error so the CLI has one thing to render.

/// Result alias for this crate.
pub type Result<T, E = Error> = core::result::Result<T, E>;

/// Something went wrong orchestrating.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// Config was missing or malformed.
    #[error("configuration error: {detail}")]
    Config {
        /// What was wrong. Names a key, never a value — config can hold
        /// endpoints and identifiers worth keeping out of a log.
        detail: String,
    },

    /// The keystore is locked and the operation needs it.
    #[error("locked; run `gst unlock` first")]
    Locked,

    /// A job failed after exhausting its retries.
    #[error("job `{job}` failed after {attempts} attempts")]
    JobFailed {
        /// Which job.
        job: String,
        /// How many attempts were made.
        attempts: u32,
    },

    /// This device is a replica and the operation requires the sealer.
    ///
    /// The user-facing form of the single-sealer rule (SPEC Q10). Says which
    /// device *is* the sealer, because otherwise this is an error with no
    /// obvious next step.
    #[error("this device is a replica; `{sealer}` is the sealing device")]
    NotSealer {
        /// The registered sealing device.
        sealer: String,
    },

    /// Crypto failed.
    #[error(transparent)]
    Crypto(#[from] ghostr_crypto::Error),
    /// The store failed.
    #[error(transparent)]
    Store(#[from] ghostr_store::Error),
    /// A model call failed.
    #[error(transparent)]
    Llm(#[from] ghostr_llm::Error),
    /// Ingest failed.
    #[error(transparent)]
    Ingest(#[from] ghostr_ingest::Error),
    /// Memoria failed.
    #[error(transparent)]
    Memoria(#[from] ghostr_memoria::Error),
    /// Persona work failed.
    #[error(transparent)]
    Persona(#[from] ghostr_persona::Error),
    /// Quest work failed.
    #[error(transparent)]
    Quests(#[from] ghostr_quests::Error),
    /// Anchoring failed.
    #[error(transparent)]
    Anchor(#[from] ghostr_anchor::Error),
    /// A relay operation failed.
    #[error(transparent)]
    Nostr(#[from] ghostr_nostr::Error),
}
