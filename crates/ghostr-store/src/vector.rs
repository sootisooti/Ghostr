//! [`VectorIndex`] — the local embedding index.
//!
//! Embeddings are treated as content, not as metadata. They are invertible
//! enough to reconstruct a great deal of the text they came from, which is why
//! embedding is local-only with no remote path at all — not even for `Public`
//! memories, because a single rule has no failure mode (SPEC Q13).

use async_trait::async_trait;
use ghostr_core::ids::{MemoryId, VectorId};
use serde::{Deserialize, Serialize};

/// Nearest-neighbour search over locally computed embeddings.
#[async_trait]
pub trait VectorIndex: Send + Sync {
    /// Inserts or replaces an embedding.
    ///
    /// # Errors
    ///
    /// Returns an error if the write fails.
    async fn upsert(&self, memory: MemoryId, embedding: &[f32]) -> crate::Result<VectorId>;

    /// The `k` nearest memories to a query vector.
    ///
    /// # Errors
    ///
    /// Returns an error if the query dimension does not match the index.
    async fn knn(
        &self,
        query: &[f32],
        k: u32,
        filter: &VectorFilter,
    ) -> crate::Result<Vec<Neighbor>>;

    /// Removes an embedding.
    ///
    /// Called by [`MemoryStore::shred`](crate::MemoryStore::shred). A shredded
    /// memory whose embedding survived would still be reconstructible from the
    /// index, which would make the shred a lie.
    ///
    /// # Errors
    ///
    /// Returns an error if the delete fails.
    async fn remove(&self, memory: MemoryId) -> crate::Result<()>;

    /// Rebuilds the index from scratch.
    ///
    /// Needed when the embedding model changes, which it will. Must be resumable:
    /// re-embedding a multi-year corpus on a local model is measured in hours,
    /// and a rebuild that cannot survive a laptop lid closing is a rebuild
    /// nobody completes.
    ///
    /// # Errors
    ///
    /// Returns an error if the rebuild fails, leaving the previous index intact.
    async fn rebuild(&self, model: &str, dimensions: u32) -> crate::Result<RebuildProgress>;

    /// The index's current model and dimensionality.
    ///
    /// # Errors
    ///
    /// Returns an error if the read fails.
    async fn descriptor(&self) -> crate::Result<IndexDescriptor>;
}

/// Restrictions applied during a nearest-neighbour search.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct VectorFilter {
    /// Only these memories.
    pub only: Vec<MemoryId>,
    /// Never these memories.
    ///
    /// Used to exclude held-out quest evidence from retrieval, so the holdout
    /// does not leak back through similarity search (SPEC Q18).
    pub exclude: Vec<MemoryId>,
    /// Minimum cosine similarity.
    pub min_similarity: Option<f32>,
}

/// One nearest-neighbour result.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Neighbor {
    /// Which memory.
    pub memory: MemoryId,
    /// Cosine similarity in `-1.0..=1.0`.
    pub similarity: f32,
}

/// Progress through a rebuild.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RebuildProgress {
    /// Embeddings written so far.
    pub completed: u64,
    /// Total to write.
    pub total: u64,
}

/// What model an index was built with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexDescriptor {
    /// Model identifier.
    pub model: String,
    /// Vector dimensionality.
    pub dimensions: u32,
    /// How many vectors are stored.
    pub count: u64,
}
