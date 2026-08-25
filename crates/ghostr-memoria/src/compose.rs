//! Stage 4: assembling extractions into a draft footage.
//!
//! Composition is where the hallucination guard lives. Every claim that reaches
//! a draft must carry at least one `memory_id`, and the ones that do not are
//! dropped here rather than caught in validation — validation is the backstop,
//! not the filter (SPEC §6).

use ghostr_core::footage::{MoodReading, Thread};
use ghostr_core::ids::ThreadId;

use crate::extract::{Cluster, ClusterExtraction};

/// Assembles extractions into a draft.
pub trait Composer: Send + Sync {
    /// Ranks clusters into highlights, dropping any with no evidence.
    fn highlights(
        &self,
        pairs: &[(Cluster, ClusterExtraction)],
    ) -> Vec<ghostr_core::footage::Highlight>;

    /// Rolls up per-cluster mood into one reading.
    ///
    /// Stated contributions outweigh inferred ones rather than being averaged
    /// with them. Averaging "I had a good day" against three inferred-negative
    /// clusters produces a reading the user would not recognise.
    fn mood(&self, contributions: &[ClusterExtraction]) -> MoodReading;

    /// Diffs today's threads against yesterday's to find closed loops.
    ///
    /// Matching is by [`ThreadId`], never by title. Titles drift as a thread
    /// develops, and matching on them would either lose the thread or merge two.
    fn threads(
        &self,
        previous_open: &[Thread],
        signals: &[(Cluster, ClusterExtraction)],
    ) -> ThreadUpdate;
}

/// How threads changed over one day.
#[derive(Debug, Clone, PartialEq)]
pub struct ThreadUpdate {
    /// Threads open at the cutoff, new ones included.
    pub open: Vec<Thread>,
    /// Threads that closed today.
    pub closed: Vec<ThreadId>,
    /// Threads untouched long enough to look stalled.
    ///
    /// Distinguished from open because "you have not touched this in three
    /// weeks" is the useful thing to say about it.
    pub stalled: Vec<ThreadId>,
}
