//! The pipeline trait and its draft type.

use async_trait::async_trait;
use chrono::NaiveDate;
use chrono_tz::Tz;
use ghostr_core::footage::{
    Amendment, Footage, Highlight, MoodReading, OpenQuestion, PersonBeat, Thread,
};
use ghostr_core::ids::{MemoryId, PersonaVersion, ThreadId};
use ghostr_store::memory::TimeRange;

/// Compiles a window of memories into sealed footage.
#[async_trait]
pub trait MemoriaPipeline: Send + Sync {
    /// Stages 1–4: window, cluster, extract, compose.
    ///
    /// Produces a draft, which is not yet committed to anything.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ExtractionIncomplete`](crate::Error::ExtractionIncomplete)
    /// only if extraction failed for every cluster.
    async fn compile(
        &self,
        window: TimeRange,
        date: NaiveDate,
        tz: Tz,
    ) -> crate::Result<DraftFootage>;

    /// Checks a draft against the rules a footage must satisfy.
    ///
    /// Separate from [`MemoriaPipeline::compile`] on purpose: the "every
    /// highlight cites at least one memory" rule must be enforceable
    /// independently of the model that produced the draft. A model that
    /// hallucinates is not a special case here — it is the case this exists for.
    ///
    /// # Errors
    ///
    /// Returns every violation at once, so a caller can report them together
    /// rather than one per retry.
    fn validate(&self, draft: &DraftFootage) -> Result<(), Vec<ValidationError>> {
        validate_draft(draft)
    }

    /// Stage 5: seal.
    ///
    /// Computes the Merkle root, links to the previous day, and writes the
    /// footage in one transaction. **After this returns, the footage is
    /// immutable and the chain has advanced.**
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotSealer`](crate::Error::NotSealer) if this device is a
    /// replica, or [`Error::AlreadySealed`](crate::Error::AlreadySealed).
    async fn seal(&self, draft: DraftFootage) -> crate::Result<Footage>;
}

/// A compiled but uncommitted day.
///
/// Everything a [`Footage`] has except the commitment and the seal time, which
/// only exist once sealing happens.
#[derive(Debug, Clone, PartialEq)]
pub struct DraftFootage {
    /// The sequence this will occupy.
    pub seq: u64,
    /// Local calendar date.
    pub date: NaiveDate,
    /// Zone in effect.
    pub tz: Tz,
    /// The window compiled.
    pub window: TimeRange,
    /// Whether the window was empty.
    ///
    /// An empty day still seals and still advances `seq`. A gap in the chain is
    /// indistinguishable from a deletion, so there are no gaps.
    pub empty: bool,
    /// What mattered.
    pub highlights: Vec<Highlight>,
    /// Who appeared.
    pub people: Vec<PersonBeat>,
    /// The day's mood.
    pub mood: MoodReading,
    /// Threads open at the cutoff.
    pub open_threads: Vec<Thread>,
    /// Threads that closed today.
    pub closed_loops: Vec<ThreadId>,
    /// Threads carried in from the previous sealed day.
    ///
    /// Not part of the footage — it is an input to composition, kept on the
    /// draft so `ClosedLoopNeverOpened` is checkable at all. A thread that
    /// closed today has already been removed from `open_threads`, so without
    /// this the draft holds no record that it was ever open.
    pub carried_threads: Vec<ThreadId>,
    /// What the extractor could not determine.
    pub unresolved: Vec<OpenQuestion>,
    /// Every memory in the window.
    pub memory_ids: Vec<MemoryId>,
    /// Corrections to earlier sealed days.
    pub amendments: Vec<Amendment>,
    /// The persona version in force.
    pub persona_version: PersonaVersion,
}

/// A rule a draft broke.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ValidationError {
    /// A highlight cited no memory.
    ///
    /// The hallucination guard. A summary with no evidence is dropped, not
    /// stored (SPEC §6).
    HighlightWithoutEvidence {
        /// Index into the draft's highlights.
        index: usize,
    },
    /// A claim cited a memory outside the sealed window.
    EvidenceOutOfWindow {
        /// The offending memory.
        memory: MemoryId,
    },
    /// A person beat named an entity no memory in the window refers to.
    PersonWithoutEvidence {
        /// Index into the draft's people.
        index: usize,
    },
    /// An amendment targeted a sequence at or after this one.
    ///
    /// Amendments correct the *past*. One pointing forward is a bug that would
    /// let a draft rewrite a day that has not happened.
    AmendmentNotInPast {
        /// The target sequence.
        target_seq: u64,
    },
    /// A thread closed today was never opened.
    ClosedLoopNeverOpened {
        /// The offending thread.
        thread: ThreadId,
    },
    /// A numeric field fell outside its documented range.
    OutOfRange {
        /// Which field.
        field: &'static str,
    },
}

/// Checks a draft against the rules a footage must satisfy.
///
/// A free function, and the trait's default body, so the rules hold for every
/// pipeline rather than for whichever one remembered to implement them. A model
/// that hallucinates is not a special case here — it is the case this exists
/// for (SPEC §6).
///
/// # Errors
///
/// Returns every violation at once, so a caller can report them together rather
/// than one per retry.
pub fn validate_draft(draft: &DraftFootage) -> Result<(), Vec<ValidationError>> {
    use std::collections::BTreeSet;

    let mut errors = Vec::new();
    let in_window: BTreeSet<MemoryId> = draft.memory_ids.iter().copied().collect();

    for (index, highlight) in draft.highlights.iter().enumerate() {
        if highlight.memory_ids.is_empty() {
            errors.push(ValidationError::HighlightWithoutEvidence { index });
        }
        if !(0.0..=1.0).contains(&highlight.salience) {
            errors.push(ValidationError::OutOfRange {
                field: "highlight.salience",
            });
        }
        for memory in &highlight.memory_ids {
            if !in_window.contains(memory) {
                errors.push(ValidationError::EvidenceOutOfWindow { memory: *memory });
            }
        }
    }

    for (index, person) in draft.people.iter().enumerate() {
        if person.memory_ids.is_empty() {
            errors.push(ValidationError::PersonWithoutEvidence { index });
        }
        for memory in &person.memory_ids {
            if !in_window.contains(memory) {
                errors.push(ValidationError::EvidenceOutOfWindow { memory: *memory });
            }
        }
        if person.valence.is_some_and(|v| !(-1.0..=1.0).contains(&v)) {
            errors.push(ValidationError::OutOfRange {
                field: "person.valence",
            });
        }
    }

    for question in &draft.unresolved {
        for memory in &question.memory_ids {
            if !in_window.contains(memory) {
                errors.push(ValidationError::EvidenceOutOfWindow { memory: *memory });
            }
        }
    }

    if !(-1.0..=1.0).contains(&draft.mood.valence) {
        errors.push(ValidationError::OutOfRange {
            field: "mood.valence",
        });
    }
    if !(0.0..=1.0).contains(&draft.mood.arousal) {
        errors.push(ValidationError::OutOfRange {
            field: "mood.arousal",
        });
    }
    if !(0.0..=1.0).contains(&draft.mood.confidence) {
        errors.push(ValidationError::OutOfRange {
            field: "mood.confidence",
        });
    }

    for amendment in &draft.amendments {
        // Amendments correct the past. One pointing at this sequence or later
        // would let a draft rewrite a day that has not happened (I2, I3).
        if amendment.target_seq >= draft.seq {
            errors.push(ValidationError::AmendmentNotInPast {
                target_seq: amendment.target_seq,
            });
        }
    }

    // A thread may close on the day it opened, so today's own opens count.
    let opened: BTreeSet<ThreadId> = draft
        .open_threads
        .iter()
        .map(|t| t.id)
        .chain(draft.carried_threads.iter().copied())
        .collect();
    for thread in &draft.closed_loops {
        if !opened.contains(thread) {
            errors.push(ValidationError::ClosedLoopNeverOpened { thread: *thread });
        }
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

/// Removes every claim that cites no evidence, or evidence outside the window.
///
/// The filter, where [`validate_draft`] is the backstop. Dropping is the right
/// response to a hallucinated highlight: it is not a failure worth stopping a
/// day for, and a day that refuses to close would leave a gap in the chain,
/// which is worse than a slightly shorter recap (SPEC §6, I3).
///
/// Returns how many claims were dropped, so the caller can report it rather
/// than have the recap quietly shrink.
pub fn drop_unevidenced(draft: &mut DraftFootage) -> usize {
    use std::collections::BTreeSet;

    let in_window: BTreeSet<MemoryId> = draft.memory_ids.iter().copied().collect();
    let cited = |ids: &[MemoryId]| !ids.is_empty() && ids.iter().all(|m| in_window.contains(m));

    let before = draft.highlights.len() + draft.people.len() + draft.unresolved.len();
    draft.highlights.retain(|h| cited(&h.memory_ids));
    draft.people.retain(|p| cited(&p.memory_ids));
    draft.unresolved.retain(|q| cited(&q.memory_ids));
    before - (draft.highlights.len() + draft.people.len() + draft.unresolved.len())
}

#[cfg(test)]
mod tests {
    use ghostr_core::footage::{AmendmentReason, InteractionKind, MoodBasis, ThreadState};
    use ghostr_core::ids::EntityId;

    use super::*;

    fn memory_id(n: u8) -> MemoryId {
        MemoryId::new(u64::from(n), [n; 10])
    }

    fn draft() -> DraftFootage {
        DraftFootage {
            seq: 5,
            date: chrono::NaiveDate::from_ymd_opt(2026, 8, 25).expect("date"),
            tz: chrono_tz::UTC,
            window: ghostr_store::memory::TimeRange {
                start: ghostr_core::time::Timestamp::new(0, 0),
                end: ghostr_core::time::Timestamp::new(86_400_000, 0),
            },
            empty: false,
            highlights: vec![Highlight {
                summary: "fixed the parser".to_owned(),
                memory_ids: vec![memory_id(1)],
                salience: 0.8,
            }],
            people: vec![PersonBeat {
                entity: EntityId::new(1, [1u8; 10]),
                interaction: InteractionKind::Mentioned,
                valence: None,
                memory_ids: vec![memory_id(1)],
            }],
            mood: MoodReading {
                valence: 0.2,
                arousal: 0.4,
                labels: Vec::new(),
                confidence: 0.5,
                basis: MoodBasis::Inferred,
            },
            open_threads: Vec::new(),
            closed_loops: Vec::new(),
            carried_threads: Vec::new(),
            unresolved: Vec::new(),
            memory_ids: vec![memory_id(1), memory_id(2)],
            amendments: Vec::new(),
            persona_version: PersonaVersion::genesis(),
        }
    }

    #[test]
    fn a_well_formed_draft_validates() {
        assert!(validate_draft(&draft()).is_ok());
    }

    /// The hallucination guard. A summary with no evidence must never reach the
    /// chain (SPEC §6).
    #[test]
    fn a_highlight_without_evidence_is_a_violation() {
        let mut d = draft();
        d.highlights[0].memory_ids.clear();
        let errors = validate_draft(&d).expect_err("must fail");
        assert!(errors.contains(&ValidationError::HighlightWithoutEvidence { index: 0 }));
    }

    /// A citation the day cannot support is the other half of the same guard:
    /// evidence that exists but is not in this window proves nothing about it.
    #[test]
    fn evidence_from_outside_the_window_is_a_violation() {
        let mut d = draft();
        d.highlights[0].memory_ids = vec![memory_id(9)];
        let errors = validate_draft(&d).expect_err("must fail");
        assert!(errors.contains(&ValidationError::EvidenceOutOfWindow {
            memory: memory_id(9)
        }));
    }

    #[test]
    fn a_person_beat_without_evidence_is_a_violation() {
        let mut d = draft();
        d.people[0].memory_ids.clear();
        let errors = validate_draft(&d).expect_err("must fail");
        assert!(errors.contains(&ValidationError::PersonWithoutEvidence { index: 0 }));
    }

    /// Amendments correct the past. One pointing at this sequence or later
    /// would let a draft rewrite a day that has not happened (I2, I3).
    #[test]
    fn an_amendment_pointing_forward_is_a_violation() {
        let mut d = draft();
        d.amendments.push(Amendment {
            target_seq: 5,
            reason: AmendmentReason::LateArrival,
            note: "a note arrived late".to_owned(),
            memory_ids: vec![memory_id(1)],
        });
        let errors = validate_draft(&d).expect_err("must fail");
        assert!(errors.contains(&ValidationError::AmendmentNotInPast { target_seq: 5 }));
    }

    #[test]
    fn an_amendment_pointing_backward_is_fine() {
        let mut d = draft();
        d.amendments.push(Amendment {
            target_seq: 4,
            reason: AmendmentReason::LateArrival,
            note: "a note arrived late".to_owned(),
            memory_ids: vec![memory_id(1)],
        });
        assert!(validate_draft(&d).is_ok());
    }

    /// A day-3-to-day-9 loop: the thread was carried in, so closing it is
    /// legitimate even though it is no longer in `open_threads`.
    #[test]
    fn closing_a_thread_carried_in_from_an_earlier_day_is_fine() {
        let mut d = draft();
        let thread = ThreadId::new(3, [3u8; 10]);
        d.carried_threads = vec![thread];
        d.closed_loops = vec![thread];
        assert!(validate_draft(&d).is_ok());
    }

    #[test]
    fn a_closed_loop_that_was_never_opened_is_a_violation() {
        let mut d = draft();
        let ghost = ThreadId::new(9, [9u8; 10]);
        d.closed_loops = vec![ghost];
        d.carried_threads = Vec::new();
        d.open_threads = vec![Thread {
            id: ThreadId::new(1, [1u8; 10]),
            title: "something else".to_owned(),
            opened_seq: 3,
            last_touched_seq: 5,
            state: ThreadState::Open,
            memory_ids: vec![memory_id(1)],
        }];
        let errors = validate_draft(&d).expect_err("must fail");
        assert!(errors.contains(&ValidationError::ClosedLoopNeverOpened { thread: ghost }));
    }

    /// A thread opened and closed on the same day never gets carried, and must
    /// still be legitimate.
    #[test]
    fn a_thread_opened_and_closed_today_is_fine() {
        let mut d = draft();
        let thread = ThreadId::new(5, [5u8; 10]);
        d.open_threads = vec![Thread {
            id: thread,
            title: "same-day".to_owned(),
            opened_seq: 5,
            last_touched_seq: 5,
            state: ThreadState::Open,
            memory_ids: vec![memory_id(1)],
        }];
        d.closed_loops = vec![thread];
        assert!(validate_draft(&d).is_ok());
    }

    #[test]
    fn a_number_outside_its_documented_range_is_a_violation() {
        let mut d = draft();
        d.mood.valence = 5.0;
        let errors = validate_draft(&d).expect_err("must fail");
        assert!(errors.contains(&ValidationError::OutOfRange {
            field: "mood.valence"
        }));
    }

    #[test]
    fn every_violation_is_reported_at_once() {
        let mut d = draft();
        d.highlights[0].memory_ids.clear();
        d.people[0].memory_ids.clear();
        d.mood.arousal = 9.0;
        let errors = validate_draft(&d).expect_err("must fail");
        assert_eq!(
            errors.len(),
            3,
            "one retry per rule would be three round trips"
        );
    }

    /// Dropping, not failing: a day that refused to close because one claim was
    /// unsupported would leave a gap in the chain, which is worse than a
    /// shorter recap (I3).
    #[test]
    fn unevidenced_claims_are_dropped_and_counted() {
        let mut d = draft();
        d.highlights.push(Highlight {
            summary: "something the model invented".to_owned(),
            memory_ids: Vec::new(),
            salience: 0.9,
        });
        d.highlights.push(Highlight {
            summary: "cites a memory from another day".to_owned(),
            memory_ids: vec![memory_id(9)],
            salience: 0.9,
        });
        let dropped = drop_unevidenced(&mut d);
        assert_eq!(dropped, 2);
        assert_eq!(d.highlights.len(), 1);
        assert!(
            validate_draft(&d).is_ok(),
            "dropping makes the draft sealable"
        );
    }

    #[test]
    fn dropping_leaves_a_clean_draft_untouched() {
        let mut d = draft();
        assert_eq!(drop_unevidenced(&mut d), 0);
        assert_eq!(d, draft());
    }
}
