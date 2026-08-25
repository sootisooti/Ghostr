//! The durable job queue.
//!
//! At-least-once, persisted in the store, resumable across restarts. Sealing,
//! anchoring, ingest, and distillation all run through it.
//!
//! # Why durability is not optional here
//!
//! A machine that sleeps through its cutoff must seal on wake. An in-memory
//! queue would drop the job and leave a gap in the chain, which is
//! indistinguishable from a deletion (SPEC I3).
//!
//! # Why at-least-once is safe
//!
//! Every job is idempotent by construction. A repeated seal hits
//! [`Error::AlreadySealed`](ghostr_memoria::Error::AlreadySealed) and is treated
//! as success; a repeated anchor submission returns the existing pending proof;
//! a repeated ingest pull re-produces the same memories, which the store
//! deduplicates. Exactly-once would need distributed consensus for no benefit.

use async_trait::async_trait;
use ghostr_core::time::Timestamp;
use serde::{Deserialize, Serialize};

/// A unit of scheduled work.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "job")]
#[non_exhaustive]
pub enum Job {
    /// Pull from one source.
    Ingest {
        /// Which source.
        source_id: ghostr_core::ids::SourceId,
    },
    /// Compile and seal one window.
    Seal {
        /// Which sequence.
        seq: u64,
    },
    /// Submit a chain tip for timestamping.
    AnchorSubmit {
        /// Which sequence.
        seq: u64,
    },
    /// Try to upgrade a pending proof.
    ///
    /// Retried hourly for a day, then daily for a week.
    AnchorUpgrade {
        /// Which sequence.
        seq: u64,
    },
    /// Generate a day's quests.
    GenerateQuests {
        /// Which day.
        date: chrono::NaiveDate,
    },
    /// Distil a new persona version.
    Distill,
    /// Recompute the fidelity score.
    Score,
    /// Publish pending events to relays.
    Publish {
        /// Which scope.
        scope: ghostr_nostr::client::PublishScope,
    },
}

/// A durable queue.
#[async_trait]
pub trait JobQueue: Send + Sync {
    /// Enqueues a job.
    ///
    /// Enqueuing the same job twice before it runs must collapse to one entry —
    /// three missed anchor-upgrade ticks should produce one attempt, not three.
    ///
    /// # Errors
    ///
    /// Returns an error if the write fails.
    async fn enqueue(&self, job: Job, run_after: Timestamp) -> crate::Result<()>;

    /// Claims the next due job.
    ///
    /// # Errors
    ///
    /// Returns an error if the read fails.
    async fn claim(&self, now: Timestamp) -> crate::Result<Option<ClaimedJob>>;

    /// Marks a job done.
    ///
    /// # Errors
    ///
    /// Returns an error if the write fails.
    async fn complete(&self, id: JobId) -> crate::Result<()>;

    /// Marks a job failed and schedules a retry.
    ///
    /// # Errors
    ///
    /// Returns an error if the write fails.
    async fn fail(
        &self,
        id: JobId,
        error: &str,
        retry_after: Option<Timestamp>,
    ) -> crate::Result<()>;
}

/// Identifies a queued job.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct JobId(pub u64);

/// A job claimed for execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimedJob {
    /// Its identifier.
    pub id: JobId,
    /// The work.
    pub job: Job,
    /// How many times it has been attempted.
    pub attempts: u32,
    /// When it was first enqueued.
    pub enqueued_at: Timestamp,
}

/// Backoff policy for retries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetryPolicy {
    /// Attempts before giving up.
    pub max_attempts: u32,
    /// First retry delay in seconds.
    pub base_delay_seconds: u32,
    /// Cap on the delay.
    pub max_delay_seconds: u32,
}

impl RetryPolicy {
    /// Anchoring: patient, because calendars publish on their own schedule.
    #[must_use]
    pub const fn anchoring() -> Self {
        Self {
            max_attempts: 40,
            base_delay_seconds: 3600,
            max_delay_seconds: 86_400,
        }
    }

    /// Ingest: brisk, because a failed pull just retries next cycle.
    #[must_use]
    pub const fn ingest() -> Self {
        Self {
            max_attempts: 5,
            base_delay_seconds: 60,
            max_delay_seconds: 3600,
        }
    }

    /// Sealing: retries hard and never gives up quietly.
    ///
    /// A seal that fails permanently is a gap in the chain. It must surface to
    /// the user rather than expire out of a queue.
    #[must_use]
    pub const fn sealing() -> Self {
        Self {
            max_attempts: 10,
            base_delay_seconds: 300,
            max_delay_seconds: 3600,
        }
    }
}
