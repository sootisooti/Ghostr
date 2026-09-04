//! The [`IngestAdapter`] trait every source implements.

use async_trait::async_trait;
use ghostr_core::memory::Memory;
use ghostr_core::sensitivity::{Sensitivity, TrustLevel};
use ghostr_core::source::{Source, SourceKindTag, SyncCursor};
use serde::{Deserialize, Serialize};

/// Pulls from one kind of source.
#[async_trait]
pub trait IngestAdapter: Send + Sync {
    /// Which source kind this handles.
    fn kind(&self) -> SourceKindTag;

    /// Pulls a batch, advancing the cursor.
    ///
    /// Must be **resumable and idempotent**. A pull that dies halfway must be
    /// safe to repeat: the returned cursor advances only over what is in the
    /// batch, so re-running from the previous cursor re-produces the same
    /// memories rather than skipping a span.
    ///
    /// Should return bounded batches. A five-year social archive cannot be one
    /// batch — it would not fit in memory and could not be resumed.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Unreachable`](crate::Error::Unreachable) if the source
    /// cannot be read, or [`Error::InvalidCursor`](crate::Error::InvalidCursor)
    /// if the cursor does not belong to this adapter.
    async fn pull(&self, source: &Source, cursor: SyncCursor) -> crate::Result<IngestBatch>;

    /// The trust level content from this source gets by default.
    ///
    /// **A security control.** Returning [`TrustLevel::FirstParty`] for content
    /// the user did not write lets a stranger's text become a voice exemplar and
    /// source claims about what the user believes (THREAT_MODEL §T7).
    fn default_trust(&self) -> TrustLevel;

    /// The sensitivity floor for content from this source.
    ///
    /// A floor, never a ceiling: later processing may raise a memory's
    /// sensitivity and may never lower it.
    fn default_sensitivity(&self) -> Sensitivity;

    /// Whether this adapter reaches the network.
    ///
    /// Surfaced when a user adds a source, so "this will talk to the internet"
    /// is visible at the moment of the decision rather than discoverable
    /// afterwards.
    fn touches_network(&self) -> bool;

    /// Checks a source is reachable and its configuration parses.
    ///
    /// Runs at `gst source add` so a typo fails immediately instead of at 23:59.
    ///
    /// # Errors
    ///
    /// Returns an error describing what is wrong with the configuration.
    async fn validate(&self, source: &Source) -> crate::Result<()>;
}

/// One pull's worth of memories.
#[derive(Debug, Clone, PartialEq)]
pub struct IngestBatch {
    /// The memories produced, in source order.
    pub memories: Vec<Memory>,
    /// The cursor to resume from.
    ///
    /// Advances only over what is in `memories`, so a crash before the batch is
    /// stored loses work rather than skipping it.
    pub cursor: SyncCursor,
    /// Whether more remains beyond this batch.
    pub has_more: bool,
    /// Records skipped as already seen.
    pub duplicates_skipped: u32,
    /// Records that could not be parsed.
    ///
    /// Counted rather than fatal: one malformed row in a five-year archive
    /// should not abort the import. Reported so the user knows it happened.
    pub unparseable_skipped: u32,
    /// Records the source returned that the adapter did not ask for.
    ///
    /// Separate from `unparseable_skipped`, because it means something else
    /// entirely: those were malformed, these were well-formed and *wrong* — a
    /// relay answering a filter with events from another author, of another
    /// kind, or with a signature that does not check out. A networked source
    /// deciding what enters the corpus is the attack this count makes visible,
    /// so folding it into a parse-failure tally would hide the one number worth
    /// looking at (THREAT_MODEL §T7).
    pub rejected_untrusted: u32,
}

/// How an adapter derives a memory's occurrence time.
///
/// Recorded because it changes what a footage window means. A file mtime is a
/// poor proxy for when something happened, and a footage built from mtimes
/// should not silently claim the same authority as one built from real
/// timestamps.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum TimeBasis {
    /// The source stated when it happened.
    Stated,
    /// Parsed from content, e.g. a dated journal heading.
    ParsedFromContent,
    /// Filesystem modification time.
    FileMtime,
    /// Unknown; `occurred_at` is `None`.
    Unknown,
}
