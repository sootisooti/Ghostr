//! This crate's error type.

use ghostr_core::ids::QuestId;

/// Result alias for this crate.
pub type Result<T, E = Error> = core::result::Result<T, E>;

/// Something went wrong generating, answering, or scoring a quest.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// A verdict's answer commitment did not match the stored answer (SPEC I6).
    ///
    /// The verdict is rejected. Scoring it would silently launder a broken
    /// guarantee: a mismatch means the answer being scored is not the answer
    /// that was committed to before the user saw the question.
    #[error("quest {id:?} answer commitment does not verify; verdict rejected")]
    CommitmentMismatch {
        /// The offending quest.
        id: QuestId,
    },

    /// A verdict arrived for a quest that already has one.
    #[error("quest {id:?} already has a verdict")]
    AlreadyAnswered {
        /// The quest.
        id: QuestId,
    },

    /// A verdict arrived after expiry.
    #[error("quest {id:?} expired")]
    Expired {
        /// The quest.
        id: QuestId,
    },

    /// Not enough scored quests to say anything.
    ///
    /// Returned rather than reporting a meaningless number. 100% over four
    /// quests is noise, and rendering it as a score teaches the user to trust a
    /// figure that has not earned it.
    #[error("insufficient sample: {have} scored quests, need {need}")]
    InsufficientSample {
        /// Scored quests available.
        have: u32,
        /// Minimum needed.
        need: u32,
    },

    /// A scorer was handed a quest that is not held out (SPEC I7).
    ///
    /// A bug in the caller, and a load-bearing one: it means the score includes
    /// data the model trained on.
    #[error("scorer received a non-holdout quest {id:?}")]
    NonHoldoutInScore {
        /// The offending quest.
        id: QuestId,
    },

    /// The model failed to generate usable quests.
    #[error("model error")]
    Llm(#[from] ghostr_llm::Error),

    /// The store failed.
    #[error("store error")]
    Store(#[from] ghostr_store::Error),

    /// Hashing failed.
    #[error("core error")]
    Core(#[from] ghostr_core::Error),
}
