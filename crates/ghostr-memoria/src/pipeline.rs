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
    fn validate(&self, draft: &DraftFootage) -> Result<(), Vec<ValidationError>>;

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
