//! Selecting which memories go into a prompt.

use ghostr_core::ids::MemoryId;
use ghostr_core::memory::Memory;
use ghostr_core::quest::Facet;
use ghostr_core::sensitivity::Sensitivity;
use ghostr_llm::prompt::TokenBudget;

/// Chooses memories to put in front of a model.
pub trait Retriever: Send + Sync {
    /// Retrieves memories within a token budget.
    ///
    /// Two rules implementations must hold:
    ///
    /// - Never return a memory above `query.max_sensitivity`. Filtering at
    ///   retrieval means `Secret` content is not merely blocked at egress, it is
    ///   never loaded into a prompt that might be routed remotely later.
    /// - Never return a memory in `query.exclude`. That set carries held-out
    ///   quest evidence, and returning one leaks the holdout back through
    ///   similarity search (SPEC Q18).
    ///
    /// # Errors
    ///
    /// Returns an error if the store or the embedder fails.
    fn retrieve(&self, query: &RetrievalQuery, budget: TokenBudget) -> crate::Result<Vec<Memory>>;
}

/// What to retrieve.
#[derive(Debug, Clone, PartialEq)]
pub struct RetrievalQuery {
    /// Free-text query, embedded locally for similarity search.
    pub text: Option<String>,
    /// Restrict to memories bearing on this facet.
    pub facet: Option<Facet>,
    /// Hard sensitivity ceiling.
    ///
    /// Set by the caller from the *destination model's* locality, so routing
    /// decides what is loaded rather than what is filtered afterwards.
    pub max_sensitivity: Sensitivity,
    /// Never return these.
    pub exclude: Vec<MemoryId>,
    /// Prefer recent memories over similar ones, in `0.0..=1.0`.
    pub recency_bias: f32,
}

impl Default for RetrievalQuery {
    /// Defaults to the most restrictive ceiling.
    ///
    /// `Sensitivity` deliberately has no `Default` in `ghostr-core`, because the
    /// safe default depends on which direction the field points: a *ceiling*
    /// defaults low, whereas a memory's own sensitivity would default high.
    /// Writing it out here forces that choice to be made where the meaning is
    /// known, rather than inherited from a derive.
    fn default() -> Self {
        Self {
            text: None,
            facet: None,
            max_sensitivity: Sensitivity::Public,
            exclude: Vec::new(),
            recency_bias: 0.0,
        }
    }
}
