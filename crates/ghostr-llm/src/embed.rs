//! [`Embedder`] — local-only embedding.
//!
//! There is no remote embedding path and there is not going to be one. Embeddings
//! are invertible enough to reconstruct much of their source text, so sending
//! them to a provider is sending the content. The rule covers `Public` memories
//! too, because a rule with an exception is a rule with a failure mode
//! (SPEC Q13).

use async_trait::async_trait;
use ghostr_core::ids::MemoryId;
use ghostr_core::sensitivity::Sensitivity;
use serde::{Deserialize, Serialize};

/// Produces embeddings.
#[async_trait]
pub trait Embedder: Send + Sync {
    /// What this embedder is.
    fn descriptor(&self) -> EmbedderDescriptor;

    /// Embeds a batch.
    ///
    /// Implementations must assert their descriptor's locality is
    /// [`Locality::Local`](crate::model::Locality::Local). This is belt and
    /// braces next to there being no remote implementation, and it is cheap.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Transport`](crate::Error::Transport) if the local
    /// runtime cannot be reached.
    async fn embed(&self, inputs: &[EmbedInput]) -> crate::Result<Vec<Embedding>>;
}

/// One thing to embed.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EmbedInput {
    /// Which memory this is for.
    pub memory: MemoryId,
    /// The text.
    pub text: String,
    /// Its sensitivity.
    ///
    /// Carried so an implementation can assert it is local before proceeding,
    /// even though every implementation is.
    pub sensitivity: Sensitivity,
}

/// A computed embedding.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Embedding {
    /// Which memory.
    pub memory: MemoryId,
    /// The vector.
    pub vector: Vec<f32>,
}

/// What an embedder is.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmbedderDescriptor {
    /// Model identifier. Recorded in the index so a model change forces a
    /// rebuild rather than silently mixing incompatible vector spaces.
    pub model: String,
    /// Vector dimensionality.
    pub dimensions: u32,
    /// Always local.
    pub locality: crate::model::Locality,
    /// Largest batch this embedder accepts.
    pub max_batch: u32,
}
