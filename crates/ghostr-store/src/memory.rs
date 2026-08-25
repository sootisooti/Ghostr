//! [`MemoryStore`] — append-only storage for the corpus.

use async_trait::async_trait;
use ghostr_core::ids::{EntityId, MemoryId, SourceId};
use ghostr_core::memory::{Memory, MemoryKind};
use ghostr_core::sensitivity::Sensitivity;
use ghostr_core::time::Timestamp;
use serde::{Deserialize, Serialize};

/// Append-only storage for memories.
///
/// There is no `update`. A correction writes a new [`Memory`] carrying
/// `supersedes`, which keeps the record of the user changing their mind — itself
/// persona-relevant data (SPEC I2).
#[async_trait]
pub trait MemoryStore: Send + Sync {
    /// Writes a memory.
    ///
    /// # Errors
    ///
    /// Returns [`Error::AppendOnlyViolation`](crate::Error::AppendOnlyViolation)
    /// if the id already exists, or [`Error::Locked`](crate::Error::Locked).
    async fn put(&self, memory: Memory) -> crate::Result<MemoryId>;

    /// Writes many memories in one transaction.
    ///
    /// Ingest batches are all-or-nothing: a partial batch leaves a source cursor
    /// that disagrees with what was actually stored, and the next pull silently
    /// skips the difference.
    ///
    /// # Errors
    ///
    /// Returns an error if any memory fails, having written none.
    async fn put_batch(&self, memories: Vec<Memory>) -> crate::Result<Vec<MemoryId>>;

    /// Reads one memory, following supersession to the head by default.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Shredded`](crate::Error::Shredded) if the content was
    /// crypto-shredded, which is distinct from the memory not existing.
    async fn get(&self, id: MemoryId) -> crate::Result<Option<Memory>>;

    /// Reads one memory exactly as written, without following supersession.
    ///
    /// Needed by the commitment layer: a leaf commits to the memory as it was
    /// sealed, not to whatever later corrected it.
    ///
    /// # Errors
    ///
    /// Returns an error if the read fails.
    async fn get_exact(&self, id: MemoryId) -> crate::Result<Option<Memory>>;

    /// Every memory in a half-open window, sorted by id.
    ///
    /// The Memoria entry point. Half-open on absolute UTC instants so a
    /// timezone change cannot double-count or drop a memory (SPEC §6).
    ///
    /// # Errors
    ///
    /// Returns an error if the read fails.
    async fn window(&self, range: TimeRange) -> crate::Result<Vec<Memory>>;

    /// Structured search.
    ///
    /// # Errors
    ///
    /// Returns an error if the query is malformed or the read fails.
    async fn search(&self, query: &MemoryQuery) -> crate::Result<Vec<Memory>>;

    /// Crypto-shreds a memory: deletes its content and its salt, keeps its leaf.
    ///
    /// This is the operation that lets deletion and an append-only chain coexist
    /// (SPEC Q6). Because leaves are salted, dropping content *and salt* leaves a
    /// hash that still verifies the chain while the commitment becomes
    /// unopenable and the content unrecoverable. The chain still records that
    /// something was there and when; nothing records what.
    ///
    /// Irreversible.
    ///
    /// # Errors
    ///
    /// Returns [`Error::MemoryNotFound`](crate::Error::MemoryNotFound) if the id
    /// is unknown.
    async fn shred(&self, id: MemoryId, reason: RedactionReason) -> crate::Result<()>;

    /// Crypto-shreds every memory referencing an entity.
    ///
    /// Backs `gst forget <person>`. Every `PersonBeat` is a claim about someone
    /// who never agreed to be modelled, and this is the mechanism that answers
    /// them (THREAT_MODEL §T10).
    ///
    /// # Errors
    ///
    /// Returns an error if the sweep fails, having shredded nothing.
    async fn shred_by_entity(
        &self,
        entity: EntityId,
        reason: RedactionReason,
    ) -> crate::Result<Vec<MemoryId>>;

    /// How many memories exist, for progress reporting and integrity checks.
    ///
    /// # Errors
    ///
    /// Returns an error if the read fails.
    async fn count(&self) -> crate::Result<u64>;
}

/// A half-open time range, `[start, end)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimeRange {
    /// Inclusive lower bound.
    pub start: Timestamp,
    /// Exclusive upper bound.
    pub end: Timestamp,
}

/// A structured memory query.
///
/// Every field is an `AND`. Deliberately not a query language: a string-based
/// query surface over encrypted rows either leaks through the query plan or
/// forces a full decrypt-and-scan, and neither is worth the expressiveness.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct MemoryQuery {
    /// Restrict to a time window.
    pub range: Option<TimeRange>,
    /// Restrict to these sources.
    pub sources: Vec<SourceId>,
    /// Restrict to these kinds.
    pub kinds: Vec<MemoryKind>,
    /// Restrict to memories referencing these entities.
    pub entities: Vec<EntityId>,
    /// Restrict to at most this sensitivity.
    ///
    /// The retrieval path sets this when assembling a prompt for a remote model,
    /// so `Secret` content is never even loaded, let alone considered for egress.
    pub max_sensitivity: Option<Sensitivity>,
    /// Minimum salience.
    pub min_salience: Option<f32>,
    /// Include memories that have been superseded.
    pub include_superseded: bool,
    /// Maximum rows to return.
    pub limit: Option<u32>,
}

/// Why a memory was shredded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum RedactionReason {
    /// The user asked for it to be forgotten.
    UserRequest,
    /// A person in the corpus asked to be forgotten.
    ThirdPartyRequest,
    /// A secret was detected after storage.
    SecretDetected,
    /// A retention policy expired it.
    RetentionPolicy,
}
