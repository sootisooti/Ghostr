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

/// Turns a verdict into corpus and training signal.
///
/// Pure: takes the quest and the verdict, returns what should happen. The
/// store write is the engine's job, which is what lets every rule below be
/// tested without a database.
///
/// # The two rules that matter
///
/// **The commitment is verified first.** A verdict whose quest cannot produce
/// its own committed answer is rejected outright. Without that check the
/// commitment is a value nobody compares against — decoration rather than a
/// guarantee (SPEC I6).
///
/// **A held-out verdict never produces a delta.** Held-out quests are scored
/// and never trained on, and this is the point where that is enforced rather
/// than assumed upstream (SPEC I7).
#[derive(Debug, Clone, Copy, Default)]
pub struct StandardIntake;

/// How much weight one correction carries.
///
/// Small on purpose. A single correction never overturns a stance backed by
/// fifty memories; it lowers `strength` and adds to `contradicted_by` until the
/// weight genuinely shifts (SPEC §4.5).
pub const CORRECTION_WEIGHT: f32 = 0.1;

impl StandardIntake {
    /// Decides what a verdict produces.
    ///
    /// `committed_answer` is what the ghost claimed, needed to verify the
    /// commitment. The caller holds it because the quest stores only the
    /// digest — which is the whole reason the digest is stored.
    ///
    /// # Errors
    ///
    /// Returns [`Error::CommitmentMismatch`](crate::Error::CommitmentMismatch)
    /// if the quest cannot reproduce its commitment,
    /// [`Error::AlreadyAnswered`](crate::Error::AlreadyAnswered), or
    /// [`Error::Expired`](crate::Error::Expired).
    pub fn decide(
        &self,
        quest: &ghostr_core::quest::Quest,
        committed_answer: &str,
        verdict: &Verdict,
        answered_at: Timestamp,
        latency_floor_seconds: f32,
    ) -> crate::Result<VerdictOutcome> {
        use ghostr_core::quest::QuestStatus;

        // Verified before anything else is looked at. A mismatch means either
        // the store was tampered with or the client is presenting a different
        // claim than the one committed to, and both make the answer worthless.
        if !crate::generate::verify_commitment(quest, committed_answer, quest.confidence)? {
            return Err(crate::Error::CommitmentMismatch { id: quest.id });
        }
        if quest.verdict.is_some() || quest.status == QuestStatus::Answered {
            return Err(crate::Error::AlreadyAnswered { id: quest.id });
        }
        if answered_at.utc_millis() > quest.expires_at.utc_millis() {
            return Err(crate::Error::Expired { id: quest.id });
        }

        let elapsed = (answered_at.utc_millis() - quest.issued_at.utc_millis()) as f32 / 1_000.0;

        Ok(VerdictOutcome {
            memory: None,
            // I7. A held-out correction is scored and never trained on. The
            // check is here, at the point of application, rather than assumed
            // of every caller upstream.
            delta: (!quest.holdout)
                .then(|| delta_for(quest, verdict, answered_at))
                .flatten(),
            // Decoys are excluded from the score by construction: the claim was
            // deliberately wrong, so the ghost cannot be right about it.
            scored: quest.holdout && !quest.decoy,
            decoy_confirmed: quest.decoy && matches!(verdict, Verdict::Confirm),
            // Flagged, never scored differently. Adjusting the score silently
            // would hide the signal a reader needs in order to discount it.
            suspiciously_fast: elapsed >= 0.0 && elapsed < latency_floor_seconds,
        })
    }

    /// The memory a correction contributes to the corpus.
    ///
    /// Corrections are first-party utterance data and among the highest-quality
    /// signal in the system, so they enter the corpus — which means answering
    /// quests changes the corpus that generates quests. That loop is deliberate
    /// and the memory is tagged, so distillation can weight verdict-derived
    /// content separately (SPEC Q18).
    ///
    /// Returns `None` for a verdict that carries no words of the user's own:
    /// there is nothing to store, and a placeholder would be the ghost putting
    /// text in its owner's mouth.
    #[must_use]
    pub fn correction_memory(
        quest: &ghostr_core::quest::Quest,
        verdict: &Verdict,
        source: ghostr_core::ids::SourceId,
        at: Timestamp,
        id: ghostr_core::ids::MemoryId,
        salt: [u8; 32],
    ) -> Option<Memory> {
        use ghostr_core::hash::{Tag, tagged_hash};
        use ghostr_core::memory::{MemoryBody, MemoryKind, Provenance};
        use ghostr_core::sensitivity::Sensitivity;

        let text = match verdict {
            Verdict::Correct { correction, .. } => correction.clone(),
            Verdict::Reject { note: Some(note) } => note.clone(),
            // Confirm, Unknown, an unexplained Reject, and Void carry no words
            // of the user's own.
            _ => return None,
        };
        if text.trim().is_empty() {
            return None;
        }

        Some(Memory {
            id,
            source_id: source,
            occurred_at: Some(at),
            ingested_at: at,
            kind: MemoryKind::Utterance,
            body: MemoryBody {
                text: text.clone(),
                structured: None,
                redactions: Vec::new(),
            },
            entities: Vec::new(),
            // High: the user wrote this deliberately, in response to a specific
            // claim. It is the least ambiguous signal the corpus receives.
            salience: 0.9,
            sensitivity: Sensitivity::Private,
            provenance: Provenance {
                source_id: source,
                // Names the quest it answered, so distillation can weight
                // verdict-derived memories separately and a reader can trace
                // any claim back to the question that produced it.
                external_id: Some(format!("verdict:{}", quest.id)),
                url: None,
                raw_hash: tagged_hash(
                    Tag::MemoryLeaf,
                    format!("{}\u{0}{text}", quest.id).as_bytes(),
                ),
            },
            salt,
            supersedes: None,
            embedding: None,
        })
    }
}

/// The delta a non-holdout verdict queues.
fn delta_for(
    quest: &ghostr_core::quest::Quest,
    verdict: &Verdict,
    at: Timestamp,
) -> Option<PersonaDelta> {
    // A confirmation is not a correction. Queuing one would let agreement
    // accumulate weight, and a stance the user merely failed to object to
    // would drift upward on its own.
    let weight = match verdict {
        Verdict::Correct { severity, .. } => match severity {
            ghostr_core::quest::Severity::Minor => CORRECTION_WEIGHT,
            ghostr_core::quest::Severity::Major => CORRECTION_WEIGHT * 2.0,
        },
        Verdict::Reject { .. } => CORRECTION_WEIGHT * 3.0,
        Verdict::Confirm | Verdict::Unknown => return None,
        // A broken question tells us nothing about the ghost.
        Verdict::Void { .. } => return None,
        _ => return None,
    };

    Some(PersonaDelta {
        facet: quest.facet,
        memory_id: quest.evidence.first().copied()?,
        weight,
        queued_at: at,
        // False by construction: this function is only reached for
        // non-holdout quests. Carried explicitly so the invariant is
        // checkable at the point of application rather than assumed
        // (SPEC I7).
        from_holdout: false,
    })
}

#[cfg(test)]
mod tests {
    use ghostr_core::ids::SourceId;
    use ghostr_core::quest::{Severity, Verdict};

    use crate::score::fixtures::quest as base_quest;

    use super::*;

    /// A quest with a real commitment over `answer`.
    fn committed(answer: &str, holdout: bool, decoy: bool) -> ghostr_core::quest::Quest {
        let mut q = base_quest(1, ghostr_core::quest::Facet::Opinion, None);
        q.status = ghostr_core::quest::QuestStatus::Open;
        q.holdout = holdout;
        q.decoy = decoy;
        q.evidence = vec![ghostr_core::ids::MemoryId::new(1, [1u8; 10])];
        q.answer_commitment =
            crate::generate::commit_answer(&q, answer, q.confidence, &q.nonce).expect("commit");
        q
    }

    fn at(seconds: i64) -> Timestamp {
        Timestamp::new(seconds * 1_000, 0)
    }

    /// SPEC I7. This is the point where "held out means never trained on"
    /// stops being a convention and becomes a check.
    #[test]
    fn a_held_out_verdict_never_produces_a_delta() {
        let quest = committed("prefers it", true, false);
        let outcome = StandardIntake
            .decide(
                &quest,
                "prefers it",
                &Verdict::Correct {
                    correction: "actually I dislike it".to_owned(),
                    severity: Severity::Major,
                },
                at(60),
                2.0,
            )
            .expect("accept");

        assert!(
            outcome.delta.is_none(),
            "a holdout correction was queued for training"
        );
        assert!(outcome.scored, "and it must still be scored");
    }

    /// The same correction on a non-holdout quest does train.
    #[test]
    fn a_non_holdout_correction_queues_a_delta() {
        let quest = committed("prefers it", false, false);
        let outcome = StandardIntake
            .decide(
                &quest,
                "prefers it",
                &Verdict::Correct {
                    correction: "actually I dislike it".to_owned(),
                    severity: Severity::Major,
                },
                at(60),
                2.0,
            )
            .expect("accept");

        let delta = outcome.delta.expect("a delta");
        assert!(!delta.from_holdout);
        assert_eq!(delta.facet, quest.facet);
        assert!(!outcome.scored, "and a non-holdout quest is not scored");
    }

    /// SPEC I6. A verdict against a quest that cannot reproduce its commitment
    /// is refused, which is what makes the pre-commitment real.
    #[test]
    fn a_mismatched_commitment_is_refused() {
        let mut quest = committed("prefers it", true, false);
        quest.answer_commitment = ghostr_core::hash::Hash32::zero();

        let err = StandardIntake
            .decide(&quest, "prefers it", &Verdict::Confirm, at(60), 2.0)
            .expect_err("must refuse");
        assert!(matches!(err, crate::Error::CommitmentMismatch { .. }));
    }

    /// And presenting a different answer than the one committed to is the same
    /// failure — this is the attack the commitment exists to stop.
    #[test]
    fn presenting_a_different_answer_is_refused() {
        let quest = committed("prefers it", true, false);
        assert!(matches!(
            StandardIntake.decide(&quest, "dislikes it", &Verdict::Confirm, at(60), 2.0),
            Err(crate::Error::CommitmentMismatch { .. })
        ));
    }

    #[test]
    fn an_already_answered_quest_is_refused() {
        let mut quest = committed("prefers it", true, false);
        quest.verdict = Some(Verdict::Confirm);
        assert!(matches!(
            StandardIntake.decide(&quest, "prefers it", &Verdict::Confirm, at(60), 2.0),
            Err(crate::Error::AlreadyAnswered { .. })
        ));
    }

    #[test]
    fn a_verdict_after_expiry_is_refused() {
        let quest = committed("prefers it", true, false);
        let past_expiry = Timestamp::new(quest.expires_at.utc_millis() + 1, 0);
        assert!(matches!(
            StandardIntake.decide(&quest, "prefers it", &Verdict::Confirm, past_expiry, 2.0),
            Err(crate::Error::Expired { .. })
        ));
    }

    /// A decoy is a deliberately wrong claim, so it cannot be scored — but
    /// confirming one is surfaced immediately, because a user who is
    /// rubber-stamping benefits from finding out today.
    #[test]
    fn confirming_a_decoy_is_surfaced_and_not_scored() {
        let quest = committed("prefers it", false, true);
        let outcome = StandardIntake
            .decide(&quest, "prefers it", &Verdict::Confirm, at(60), 2.0)
            .expect("accept");

        assert!(outcome.decoy_confirmed);
        assert!(!outcome.scored);
    }

    /// Flagged, never scored differently. Adjusting the score silently would
    /// remove the signal a reader needs in order to discount it.
    #[test]
    fn a_fast_verdict_is_flagged_but_still_counts() {
        let quest = committed("prefers it", true, false);
        let outcome = StandardIntake
            .decide(&quest, "prefers it", &Verdict::Confirm, at(1), 2.0)
            .expect("accept");

        assert!(outcome.suspiciously_fast);
        assert!(outcome.scored, "it is flagged, not excluded");
    }

    /// Agreement must not accumulate weight, or a stance the user merely failed
    /// to object to would drift upward on its own.
    #[test]
    fn a_confirmation_queues_nothing() {
        let quest = committed("prefers it", false, false);
        let outcome = StandardIntake
            .decide(&quest, "prefers it", &Verdict::Confirm, at(60), 2.0)
            .expect("accept");
        assert!(outcome.delta.is_none());
    }

    /// A single correction never overturns a stance backed by fifty memories.
    #[test]
    fn a_rejection_weighs_more_than_a_minor_correction_but_stays_small() {
        let quest = committed("prefers it", false, false);
        let weight = |v: Verdict| {
            StandardIntake
                .decide(&quest, "prefers it", &v, at(60), 2.0)
                .expect("accept")
                .delta
                .map(|d| d.weight)
        };

        let minor = weight(Verdict::Correct {
            correction: "nearly".to_owned(),
            severity: Severity::Minor,
        })
        .expect("a delta");
        let major = weight(Verdict::Correct {
            correction: "no".to_owned(),
            severity: Severity::Major,
        })
        .expect("a delta");
        let reject = weight(Verdict::Reject { note: None }).expect("a delta");

        assert!(minor < major);
        assert!(major < reject);
        assert!(reject < 0.5, "one answer must not overturn a stance");
    }

    /// Corrections are first-party utterance data and among the highest-quality
    /// signal the corpus receives.
    #[test]
    fn a_correction_becomes_a_memory_tagged_with_its_quest() {
        let quest = committed("prefers it", true, false);
        let memory = StandardIntake::correction_memory(
            &quest,
            &Verdict::Correct {
                correction: "I would have said the opposite".to_owned(),
                severity: Severity::Major,
            },
            SourceId::new(1, [0u8; 10]),
            at(60),
            ghostr_core::ids::MemoryId::new(5, [5u8; 10]),
            [5u8; 32],
        )
        .expect("a memory");

        assert_eq!(memory.body.text, "I would have said the opposite");
        assert!(memory.salience > 0.8);
        assert_eq!(
            memory.provenance.external_id,
            Some(format!("verdict:{}", quest.id)),
            "distillation must be able to weight verdict-derived memories separately"
        );
    }

    /// A verdict with no words of the user's own stores nothing. A placeholder
    /// would be the ghost putting text in its owner's mouth.
    #[test]
    fn a_verdict_carrying_no_words_stores_nothing() {
        let quest = committed("prefers it", true, false);
        for verdict in [
            Verdict::Confirm,
            Verdict::Unknown,
            Verdict::Reject { note: None },
            Verdict::Correct {
                correction: "   ".to_owned(),
                severity: Severity::Minor,
            },
        ] {
            assert!(
                StandardIntake::correction_memory(
                    &quest,
                    &verdict,
                    SourceId::new(1, [0u8; 10]),
                    at(60),
                    ghostr_core::ids::MemoryId::new(5, [5u8; 10]),
                    [5u8; 32],
                )
                .is_none(),
                "{verdict:?} produced a memory"
            );
        }
    }
}
