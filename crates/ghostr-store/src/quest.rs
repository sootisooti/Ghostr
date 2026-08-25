//! [`QuestStore`] — issued quests, verdicts, and the holdout set.

use async_trait::async_trait;
use chrono::NaiveDate;
use ghostr_core::ids::QuestId;
use ghostr_core::quest::{Quest, Verdict};
use ghostr_core::time::Timestamp;

/// Storage for quests and their verdicts.
///
/// Two operations carry the product's integrity guarantees and should be read
/// carefully: [`QuestStore::issue`] persists the answer commitment before the
/// quest can be displayed, and [`QuestStore::holdout_set`] is the only source a
/// scorer may draw from.
#[async_trait]
pub trait QuestStore: Send + Sync {
    /// Persists newly generated quests, commitments included.
    ///
    /// Called *before* anything is shown to the user. That ordering is what
    /// makes the pre-commitment real: a client that could display a quest before
    /// its commitment was durable could adjust the ghost's answer after seeing
    /// the user's (SPEC I6).
    ///
    /// # Errors
    ///
    /// Returns [`Error::AppendOnlyViolation`](crate::Error::AppendOnlyViolation)
    /// if any id already exists.
    async fn issue(&self, quests: Vec<Quest>) -> crate::Result<()>;

    /// Quests awaiting a verdict, oldest first.
    ///
    /// # Errors
    ///
    /// Returns an error if the read fails.
    async fn list_open(&self, as_of: Timestamp) -> crate::Result<Vec<Quest>>;

    /// Records a verdict.
    ///
    /// Implementations must verify the answer commitment before accepting, and
    /// reject on mismatch. Rejecting is correct even though it is inconvenient:
    /// a mismatch means the stored answer is not the one that was committed to,
    /// and scoring it would silently launder a broken guarantee.
    ///
    /// # Errors
    ///
    /// Returns [`Error::AppendOnlyViolation`](crate::Error::AppendOnlyViolation)
    /// if the quest already has a verdict.
    async fn record_verdict(
        &self,
        id: QuestId,
        verdict: Verdict,
        answered_at: Timestamp,
    ) -> crate::Result<()>;

    /// Held-out, non-decoy, answered quests in a date range.
    ///
    /// The *only* input a scorer may use. Anything else is grading the ghost on
    /// its own training data (SPEC I7).
    ///
    /// # Errors
    ///
    /// Returns an error if the read fails.
    async fn holdout_set(&self, from: NaiveDate, to: NaiveDate) -> crate::Result<Vec<Quest>>;

    /// Answered decoy quests in a range, for the rubber-stamp signal.
    ///
    /// # Errors
    ///
    /// Returns an error if the read fails.
    async fn decoy_set(&self, from: NaiveDate, to: NaiveDate) -> crate::Result<Vec<Quest>>;

    /// Non-held-out corrections eligible to feed persona distillation.
    ///
    /// The complement of [`QuestStore::holdout_set`], and the boundary that keeps
    /// the holdout meaningful. Implementations must also exclude
    /// verdict-derived memories from the evidence pool of held-out quests, or
    /// the holdout leaks back through the corpus (SPEC Q18).
    ///
    /// # Errors
    ///
    /// Returns an error if the read fails.
    async fn trainable_corrections(&self, since: Timestamp) -> crate::Result<Vec<Quest>>;

    /// Marks expired quests, returning how many were closed.
    ///
    /// # Errors
    ///
    /// Returns an error if the write fails.
    async fn expire_stale(&self, as_of: Timestamp) -> crate::Result<u32>;
}
