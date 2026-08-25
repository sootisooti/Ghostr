//! What runs when.

use chrono::NaiveDate;
use ghostr_core::time::Timestamp;
use serde::{Deserialize, Serialize};

use crate::jobs::Job;

/// Decides which jobs are due.
///
/// Pure: given a clock reading and the last-run times, it returns the jobs to
/// enqueue. That keeps "did the cutoff fire correctly at a DST boundary"
/// testable without waiting for one.
pub trait Scheduler: Send + Sync {
    /// Jobs due at `now`.
    fn due(&self, now: Timestamp, state: &ScheduleState) -> Vec<Job>;

    /// When to wake next.
    ///
    /// Returning an instant rather than sleeping a fixed interval means a
    /// machine can idle until the cutoff rather than polling.
    fn next_wake(&self, now: Timestamp, state: &ScheduleState) -> Timestamp;
}

/// What has run, and when.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScheduleState {
    /// Last sealed sequence and when.
    pub last_seal: Option<(u64, Timestamp)>,
    /// Last day quests were issued for.
    pub last_quest_issue: Option<NaiveDate>,
    /// Last distillation.
    pub last_distill: Option<Timestamp>,
    /// Last pull per source.
    pub last_ingest: Vec<(ghostr_core::ids::SourceId, Timestamp)>,
    /// Sequences with unconfirmed anchors.
    pub pending_anchors: Vec<u64>,
}
