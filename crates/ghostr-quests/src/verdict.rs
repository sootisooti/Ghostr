//! Taking the user's answer, and turning it into training signal.

use async_trait::async_trait;
use ghostr_core::ids::QuestId;
use ghostr_core::memory::Memory;
use ghostr_core::persona::PersonaDelta;
use ghostr_core::quest::Verdict;
use ghostr_core::time::Timestamp;

/// Accepts verdicts and converts them into corpus and deltas.
#[async_trait]
pub trait VerdictIntake: Send + Sync {
    /// Records a verdict.
    ///
    /// Verifies the answer commitment first and **rejects on mismatch**. This is
    /// the check that makes the pre-commitment real rather than decorative
    /// (SPEC I6).
    ///
    /// # Errors
    ///
    /// Returns [`Error::CommitmentMismatch`](crate::Error::CommitmentMismatch),
    /// [`Error::AlreadyAnswered`](crate::Error::AlreadyAnswered), or
    /// [`Error::Expired`](crate::Error::Expired).
    async fn accept(
        &self,
        id: QuestId,
        verdict: Verdict,
        answered_at: Timestamp,
    ) -> crate::Result<VerdictOutcome>;
}

/// What a verdict produced.
#[derive(Debug, Clone, PartialEq)]
pub struct VerdictOutcome {
    /// The memory written from the correction, if any.
    ///
    /// Corrections are first-party utterance data and among the highest-quality
    /// signal in the system, so they enter the corpus — which means answering
    /// quests changes the corpus that generates quests. That loop is deliberate
    /// and tagged, so distillation can weight verdict-derived memories
    /// separately (SPEC Q18).
    pub memory: Option<Memory>,
    /// The delta queued against the persona, if any.
    ///
    /// Always `None` for a held-out quest. Held-out corrections are scored and
    /// never trained on (SPEC I7).
    pub delta: Option<PersonaDelta>,
    /// Whether this quest counts toward the fidelity score.
    pub scored: bool,
    /// Whether the user confirmed a decoy.
    ///
    /// Surfaced immediately rather than only in aggregate, because a user who is
    /// rubber-stamping benefits from finding out today.
    pub decoy_confirmed: bool,
    /// Whether the verdict came back faster than the latency floor.
    pub suspiciously_fast: bool,
}
