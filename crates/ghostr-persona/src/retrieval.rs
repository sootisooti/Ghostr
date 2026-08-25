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

/// Selects memories by similarity, recency, and salience.
///
/// Takes the candidate set rather than reaching for a store: the engine owns
/// the store and the vector index, and this crate has no business holding a
/// database handle. What lives here is the *policy* — the two rules below — and
/// keeping it separable is what lets it be tested exhaustively without one.
///
/// # The two rules, enforced before ranking
///
/// Both filters run before any scoring, and that ordering is deliberate. A
/// filter applied after ranking is a filter that has already loaded the thing
/// it was meant to exclude, and one `if` away from returning it.
#[derive(Debug, Default, Clone, Copy)]
pub struct PolicyRetriever;

/// One candidate, with its similarity to the query if one was computed.
#[derive(Debug, Clone)]
pub struct Candidate<'a> {
    /// The memory.
    pub memory: &'a Memory,
    /// Cosine similarity in `-1.0..=1.0`, or `None` for a query with no text.
    pub similarity: Option<f32>,
}

/// Roughly four characters per token, matching [`TokenBudget::chars`].
const CHARS_PER_TOKEN: usize = 4;

impl PolicyRetriever {
    /// Filters and ranks candidates within a budget.
    ///
    /// Returns the memories in the order they should enter a prompt: most
    /// relevant first, so that if the budget truncates, what survives is what
    /// mattered most.
    #[must_use]
    pub fn select<'a>(
        &self,
        query: &RetrievalQuery,
        candidates: &[Candidate<'a>],
        budget: TokenBudget,
    ) -> Vec<&'a Memory> {
        let excluded: std::collections::BTreeSet<MemoryId> =
            query.exclude.iter().copied().collect();

        let mut kept: Vec<(&Candidate<'a>, f32)> = candidates
            .iter()
            // Rule 1: never above the ceiling. Filtering at retrieval means
            // `Secret` content is not merely blocked at egress — it is never
            // loaded into a prompt that might be routed remotely later.
            .filter(|c| c.memory.sensitivity <= query.max_sensitivity)
            // Rule 2: never a held-out memory. Returning one leaks the holdout
            // back through similarity search, and the fidelity score is then
            // computed on data the model saw (SPEC Q18).
            .filter(|c| !excluded.contains(&c.memory.id))
            .map(|c| (c, score(query, c, candidates)))
            .collect();

        kept.sort_by(|a, b| {
            b.1.partial_cmp(&a.1)
                .unwrap_or(core::cmp::Ordering::Equal)
                // Ties break on id so the selection is total and reproducible:
                // a retrieval set that varied between runs would make every
                // prompt below it non-reproducible.
                .then_with(|| a.0.memory.id.cmp(&b.0.memory.id))
        });

        let mut used = 0usize;
        let mut out = Vec::new();
        for (candidate, _) in kept {
            let cost = candidate.memory.body.text.len();
            if used + cost > budget.chars() {
                // Whole memories only. Half a note is worse input than no note,
                // and a truncated one would misrepresent what the user wrote.
                continue;
            }
            used += cost;
            out.push(candidate.memory);
        }
        out
    }

    /// How many tokens a set of memories would cost.
    #[must_use]
    pub fn cost(memories: &[&Memory]) -> u32 {
        let chars: usize = memories.iter().map(|m| m.body.text.len()).sum();
        u32::try_from(chars / CHARS_PER_TOKEN).unwrap_or(u32::MAX)
    }
}

/// Ranks one candidate.
///
/// Similarity and recency, blended by `recency_bias`. Salience breaks the
/// remaining ties, so a note the user marked important beats one they did not
/// when nothing else separates them.
fn score(query: &RetrievalQuery, candidate: &Candidate<'_>, all: &[Candidate<'_>]) -> f32 {
    let similarity = candidate.similarity.unwrap_or(0.0).clamp(-1.0, 1.0);
    let bias = query.recency_bias.clamp(0.0, 1.0);

    // Recency is relative to the candidate set, not to now: a corpus that is
    // entirely old should still rank its newest members highest, and an
    // absolute decay would flatten all of them to zero.
    let times: Vec<i64> = all
        .iter()
        .filter_map(|c| c.memory.occurred_at.map(|t| t.utc_millis()))
        .collect();
    let recency = match (times.iter().min(), times.iter().max()) {
        (Some(oldest), Some(newest)) if newest > oldest => candidate
            .memory
            .occurred_at
            .map(|t| (t.utc_millis() - oldest) as f32 / (newest - oldest) as f32)
            .unwrap_or(0.0),
        _ => 0.0,
    };

    (1.0 - bias) * similarity + bias * recency + candidate.memory.salience * 0.001
}

#[cfg(test)]
mod tests {
    use ghostr_core::sensitivity::Sensitivity;

    use crate::distill::fixtures::memory;

    use super::*;

    fn candidate(m: &Memory, similarity: f32) -> Candidate<'_> {
        Candidate {
            memory: m,
            similarity: Some(similarity),
        }
    }

    fn budget() -> TokenBudget {
        TokenBudget(4096)
    }

    /// SPEC Q18, and the reason the exclusion runs before ranking: a filter
    /// applied afterwards has already loaded the thing it was meant to exclude.
    #[test]
    fn a_held_out_memory_is_never_returned() {
        let a = memory(1, "the held-out one, which is highly relevant");
        let b = memory(2, "an ordinary note");
        let candidates = vec![candidate(&a, 0.99), candidate(&b, 0.1)];

        let query = RetrievalQuery {
            max_sensitivity: Sensitivity::Secret,
            exclude: vec![a.id],
            ..RetrievalQuery::default()
        };
        let out = PolicyRetriever.select(&query, &candidates, budget());
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].id, b.id);
    }

    /// Even as the single best match, and even with budget to spare.
    #[test]
    fn a_held_out_memory_is_excluded_even_when_it_is_the_only_match() {
        let a = memory(1, "the held-out one");
        let candidates = vec![candidate(&a, 1.0)];
        let query = RetrievalQuery {
            max_sensitivity: Sensitivity::Secret,
            exclude: vec![a.id],
            ..RetrievalQuery::default()
        };
        assert!(
            PolicyRetriever
                .select(&query, &candidates, budget())
                .is_empty()
        );
    }

    /// Filtering at retrieval means `Secret` content is not merely blocked at
    /// egress — it is never loaded into a prompt that might be routed remotely.
    #[test]
    fn nothing_above_the_ceiling_is_returned() {
        let mut secret = memory(1, "resting heart rate and where I sleep");
        secret.sensitivity = Sensitivity::Secret;
        let mut private = memory(2, "an ordinary private note");
        private.sensitivity = Sensitivity::Private;
        let mut public = memory(3, "something already published");
        public.sensitivity = Sensitivity::Public;

        let candidates = vec![
            candidate(&secret, 0.9),
            candidate(&private, 0.9),
            candidate(&public, 0.9),
        ];

        let query = RetrievalQuery {
            max_sensitivity: Sensitivity::Private,
            ..RetrievalQuery::default()
        };
        let out = PolicyRetriever.select(&query, &candidates, budget());
        assert_eq!(out.len(), 2);
        assert!(out.iter().all(|m| m.sensitivity <= Sensitivity::Private));
        assert!(!out.iter().any(|m| m.id == secret.id));
    }

    /// The default ceiling is the most restrictive one, so a caller that forgot
    /// to set it gets less than it wanted rather than more.
    #[test]
    fn the_default_ceiling_admits_only_public_content() {
        let mut private = memory(1, "an ordinary private note");
        private.sensitivity = Sensitivity::Private;
        let candidates = vec![candidate(&private, 0.9)];
        let out = PolicyRetriever.select(&RetrievalQuery::default(), &candidates, budget());
        assert!(out.is_empty());
    }

    #[test]
    fn the_most_similar_memory_comes_first() {
        let a = memory(1, "barely related");
        let b = memory(2, "exactly on topic");
        let candidates = vec![candidate(&a, 0.1), candidate(&b, 0.95)];
        let query = RetrievalQuery {
            max_sensitivity: Sensitivity::Secret,
            ..RetrievalQuery::default()
        };
        let out = PolicyRetriever.select(&query, &candidates, budget());
        assert_eq!(out[0].id, b.id);
    }

    /// A corpus that is entirely old should still rank its newest members
    /// highest; an absolute decay would flatten all of them to zero.
    #[test]
    fn recency_bias_prefers_the_newest_of_an_old_corpus() {
        let old = memory(1, "an older note about the topic");
        let new = memory(300, "a newer note about the topic");
        let candidates = vec![candidate(&old, 0.9), candidate(&new, 0.5)];

        let by_similarity = RetrievalQuery {
            max_sensitivity: Sensitivity::Secret,
            recency_bias: 0.0,
            ..RetrievalQuery::default()
        };
        assert_eq!(
            PolicyRetriever.select(&by_similarity, &candidates, budget())[0].id,
            old.id
        );

        let by_recency = RetrievalQuery {
            max_sensitivity: Sensitivity::Secret,
            recency_bias: 1.0,
            ..RetrievalQuery::default()
        };
        assert_eq!(
            PolicyRetriever.select(&by_recency, &candidates, budget())[0].id,
            new.id
        );
    }

    /// Half a note is worse input than no note, so the budget drops whole
    /// memories rather than truncating one.
    #[test]
    fn the_budget_drops_whole_memories() {
        let long = memory(1, &"x".repeat(400));
        let short = memory(2, "short and relevant");
        let candidates = vec![candidate(&long, 0.5), candidate(&short, 0.9)];

        let query = RetrievalQuery {
            max_sensitivity: Sensitivity::Secret,
            ..RetrievalQuery::default()
        };
        let out = PolicyRetriever.select(&query, &candidates, TokenBudget(50));
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].id, short.id);
        assert!(!out[0].body.text.contains("xxxx"));
    }

    /// A retrieval set that varied between runs would make every prompt below
    /// it non-reproducible.
    #[test]
    fn selection_is_deterministic() {
        let a = memory(1, "one note");
        let b = memory(2, "another note");
        let c = memory(3, "a third note");
        // Identical scores, so only the tiebreak separates them.
        let candidates = vec![candidate(&a, 0.5), candidate(&b, 0.5), candidate(&c, 0.5)];
        let query = RetrievalQuery {
            max_sensitivity: Sensitivity::Secret,
            ..RetrievalQuery::default()
        };

        let first: Vec<_> = PolicyRetriever
            .select(&query, &candidates, budget())
            .iter()
            .map(|m| m.id)
            .collect();
        let second: Vec<_> = PolicyRetriever
            .select(&query, &candidates, budget())
            .iter()
            .map(|m| m.id)
            .collect();
        assert_eq!(first, second);
    }

    /// Both rules together, which is the case that actually occurs: a holdout
    /// that is also the most similar, in a corpus with secret content.
    #[test]
    fn both_rules_hold_at_once() {
        let mut held_out = memory(1, "the held-out answer, word for word");
        held_out.sensitivity = Sensitivity::Private;
        let mut secret = memory(2, "where I sleep and my resting heart rate");
        secret.sensitivity = Sensitivity::Secret;
        let ordinary = memory(3, "an ordinary note that is fine to use");

        let candidates = vec![
            candidate(&held_out, 1.0),
            candidate(&secret, 0.99),
            candidate(&ordinary, 0.2),
        ];
        let query = RetrievalQuery {
            max_sensitivity: Sensitivity::Private,
            exclude: vec![held_out.id],
            ..RetrievalQuery::default()
        };

        let out = PolicyRetriever.select(&query, &candidates, budget());
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].id, ordinary.id);
    }

    #[test]
    fn an_empty_candidate_set_returns_nothing() {
        assert!(
            PolicyRetriever
                .select(&RetrievalQuery::default(), &[], budget())
                .is_empty()
        );
    }
}
