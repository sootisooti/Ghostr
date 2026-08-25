//! [`VectorIndex`] — the local embedding index.
//!
//! Embeddings are treated as content, not as metadata. They are invertible
//! enough to reconstruct a great deal of the text they came from, which is why
//! embedding is local-only with no remote path at all — not even for `Public`
//! memories, because a single rule has no failure mode (SPEC Q13).
//!
//! # Why the vectors are encrypted, and what that costs
//!
//! Treating an embedding as content has one unavoidable consequence: an ANN
//! extension cannot index it. `sqlite-vec` and every library like it search a
//! plaintext vector table, so adopting one would mean writing the most
//! reconstructible representation of the corpus to disk in the clear — the exact
//! thing I1 exists to prevent.
//!
//! So the index is an encrypted table scanned exhaustively. Every vector is
//! stored as a unit vector, which turns cosine similarity into a dot product,
//! and a search decrypts each row and takes the dot product against the query.
//! At one person's scale that is the right trade: 100 000 memories at 768
//! dimensions is roughly 300 MB decrypted and a few hundred milliseconds per
//! query on a laptop — noticeable, but nothing next to the local model call it
//! precedes. If a corpus ever outgrows it, the fix is an encrypted ANN structure,
//! not a plaintext one.
//!
//! # Synchronous on purpose
//!
//! There is no network here and no runtime — a scan is CPU and page cache. An
//! async signature would buy nothing and would force a runtime into every caller
//! (CLAUDE.md §5, "async only where there's real I/O").

use ghostr_core::ids::{MemoryId, VectorId};
use ghostr_crypto::kdf::Dek;
use serde::{Deserialize, Serialize};

/// Nearest-neighbour search over locally computed embeddings.
pub trait VectorIndex: Send {
    /// Inserts or replaces an embedding.
    ///
    /// The vector is normalised before storage, so magnitude is discarded and
    /// only direction is kept. Cosine similarity ignores magnitude anyway, and
    /// storing one representation rather than two removes the possibility of the
    /// two disagreeing.
    ///
    /// # Errors
    ///
    /// Returns [`Error::VectorDimensionMismatch`](crate::Error::VectorDimensionMismatch)
    /// if the width is not the index's, or
    /// [`Error::Backend`](crate::Error::Backend) if the write fails.
    fn upsert(
        &self,
        dek: &Dek,
        memory: MemoryId,
        embedding: &[f32],
        id: VectorId,
        nonce: [u8; 24],
    ) -> crate::Result<VectorId>;

    /// The `k` nearest memories to a query vector.
    ///
    /// # Errors
    ///
    /// Returns [`Error::VectorDimensionMismatch`](crate::Error::VectorDimensionMismatch)
    /// if the query width does not match the index.
    fn knn(
        &self,
        dek: &Dek,
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
    fn remove(&self, memory: MemoryId) -> crate::Result<()>;

    /// Points the index at a new model and drops every vector of the old width.
    ///
    /// Does not re-embed: the index has no embedder, and forcing one in would
    /// make the store depend on `ghostr-llm`. The caller re-embeds by draining
    /// [`VectorIndex::unembedded`], which is what makes a rebuild resumable — a
    /// laptop lid closing halfway through leaves the finished vectors in place.
    ///
    /// # Errors
    ///
    /// Returns an error if the rewrite fails, leaving the previous index intact.
    fn rebuild(&self, model: &str, dimensions: u32) -> crate::Result<RebuildProgress>;

    /// Memories with no vector at the index's current width.
    ///
    /// The work queue for a rebuild or a first index build.
    ///
    /// # Errors
    ///
    /// Returns an error if the query fails.
    fn unembedded(&self, limit: u32) -> crate::Result<Vec<MemoryId>>;

    /// The index's current model and dimensionality.
    ///
    /// # Errors
    ///
    /// Returns an error if the read fails.
    fn descriptor(&self) -> crate::Result<IndexDescriptor>;
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
    /// Vectors already at the new width, kept rather than recomputed.
    pub completed: u64,
    /// Memories that need one.
    pub total: u64,
}

/// What model an index was built with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexDescriptor {
    /// Model identifier.
    ///
    /// Recorded so a model change forces a rebuild rather than silently mixing
    /// two vector spaces, which produces neighbours that are not neighbours.
    pub model: String,
    /// Vector dimensionality.
    pub dimensions: u32,
    /// How many vectors are stored.
    pub count: u64,
}

/// Scales a vector to unit length.
///
/// Returns `None` for a zero vector: it has no direction, so it has no cosine
/// similarity to anything, and storing it would make every query's top result a
/// division by zero.
#[must_use]
pub fn normalize(vector: &[f32]) -> Option<Vec<f32>> {
    let norm = vector
        .iter()
        .map(|v| f64::from(*v) * f64::from(*v))
        .sum::<f64>()
        .sqrt();
    if !norm.is_finite() || norm <= f64::EPSILON {
        return None;
    }
    Some(
        vector
            .iter()
            .map(|v| (f64::from(*v) / norm) as f32)
            .collect(),
    )
}

/// The dot product of two equal-length vectors.
///
/// On unit vectors this *is* cosine similarity, which is why
/// [`VectorIndex::upsert`] normalises before storing.
#[must_use]
pub fn dot(a: &[f32], b: &[f32]) -> f32 {
    a.iter()
        .zip(b.iter())
        .map(|(x, y)| f64::from(*x) * f64::from(*y))
        .sum::<f64>() as f32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_normalised_vector_has_unit_length() {
        let v = normalize(&[3.0, 4.0]).expect("non-zero");
        assert!((dot(&v, &v) - 1.0).abs() < 1e-6);
    }

    /// A zero vector has no direction, so it is refused rather than stored.
    #[test]
    fn a_zero_vector_has_no_direction() {
        assert!(normalize(&[0.0, 0.0, 0.0]).is_none());
    }

    #[test]
    fn cosine_of_a_vector_with_itself_is_one() {
        let a = normalize(&[1.0, 2.0, 3.0]).expect("non-zero");
        assert!((dot(&a, &a) - 1.0).abs() < 1e-6);
    }

    #[test]
    fn opposite_directions_are_minus_one() {
        let a = normalize(&[1.0, 0.0]).expect("a");
        let b = normalize(&[-1.0, 0.0]).expect("b");
        assert!((dot(&a, &b) + 1.0).abs() < 1e-6);
    }

    #[test]
    fn orthogonal_vectors_are_zero() {
        let a = normalize(&[1.0, 0.0]).expect("a");
        let b = normalize(&[0.0, 1.0]).expect("b");
        assert!(dot(&a, &b).abs() < 1e-6);
    }

    /// Magnitude is discarded, which is the property that lets one stored
    /// representation serve both insert and query.
    #[test]
    fn scaling_does_not_change_direction() {
        let a = normalize(&[1.0, 2.0, 3.0]).expect("a");
        let b = normalize(&[10.0, 20.0, 30.0]).expect("b");
        assert!((dot(&a, &b) - 1.0).abs() < 1e-6);
    }
}
