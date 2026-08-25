//! Synthetic corpora.
//!
//! Fixtures are **generated, never real**. Committing real personal data — even
//! your own, even redacted — is the one thing this project cannot walk back
//! (CLAUDE.md §4.14).

use ghostr_core::memory::Memory;
use ghostr_core::time::{Clock, Rng};

/// Generates a synthetic corpus with a known shape.
///
/// "Known shape" is what makes assertions possible: a generator that produces a
/// user with three close friends and a Tuesday running habit lets a test check
/// that the persona model *found* them.
#[derive(Debug)]
pub struct CorpusGenerator {
    days: u32,
    memories_per_day: (u32, u32),
}

impl CorpusGenerator {
    /// A generator for a run of days.
    #[must_use]
    pub fn new(days: u32) -> Self {
        Self {
            days,
            memories_per_day: (3, 12),
        }
    }

    /// Generates the corpus.
    #[must_use]
    pub fn generate(&self, clock: &dyn Clock, rng: &dyn Rng) -> SyntheticCorpus {
        todo!("generate memories with planted entities, stances and routines")
    }

    /// Includes days with no memories at all.
    ///
    /// Empty windows still seal and still advance `seq`, and that path is easy
    /// to leave untested until a user takes a weekend off (SPEC §3.4).
    #[must_use]
    pub fn with_empty_days(self, count: u32) -> Self {
        todo!("mark `count` days as empty")
    }

    /// Includes a timezone change partway through.
    ///
    /// Exercises the cutoff logic against the case it is most likely to get
    /// wrong (SPEC Q11).
    #[must_use]
    pub fn with_timezone_change(self, on_day: u32, to: chrono_tz::Tz) -> Self {
        todo!("switch the generated timezone on the given day")
    }
}

/// A generated corpus and the ground truth behind it.
#[derive(Debug, Clone, PartialEq)]
pub struct SyntheticCorpus {
    /// The memories.
    pub memories: Vec<Memory>,
    /// What the generator planted, for assertions.
    ///
    /// The reason this is worth building: a test can check that distillation
    /// recovered the stances and relationships that were deliberately put in,
    /// rather than only that it produced *something*.
    pub ground_truth: GroundTruth,
}

/// What a generator planted.
#[derive(Debug, Clone, PartialEq)]
pub struct GroundTruth {
    /// Entity names and how often each appears.
    pub entities: Vec<(String, u32)>,
    /// Topic and position pairs the corpus supports.
    pub stances: Vec<(String, String)>,
    /// Routines, as pattern and cadence in days.
    pub routines: Vec<(String, u32)>,
    /// Threads, as title, opening day, and closing day if it closes.
    pub threads: Vec<(String, u32, Option<u32>)>,
}
