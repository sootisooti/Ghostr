//! Choosing what to ask, and committing to the answer before asking.

use chrono::NaiveDate;
use ghostr_core::ids::PersonaVersion;
use ghostr_core::persona::PersonaModel;
use ghostr_core::quest::{Facet, Quest};
use ghostr_core::time::{Rng, Timestamp};
use ghostr_llm::model::CapabilityTier;
use serde::{Deserialize, Serialize};

/// Generates a day's quests.
pub trait QuestGenerator: Send + Sync {
    /// Generates `n` quests.
    ///
    /// Every returned quest must already carry its `answer_commitment` and
    /// `nonce`. The commitment is computed here, before anything can reach a
    /// display path — that ordering is the whole guarantee (SPEC I6).
    ///
    /// # Errors
    ///
    /// Returns [`Error::Llm`](crate::Error::Llm) if the model fails.
    fn generate(&self, ctx: &QuestContext<'_>, n: usize) -> crate::Result<Vec<Quest>>;

    /// Ranks facets by how much a probe would tell us.
    ///
    /// `uncertainty × staleness × coverage_debt × (1 - user_fatigue)`
    /// (SPEC §4.2). Fatigue is in the product because a user who stops answering
    /// is worse than a user who answers fewer.
    fn prioritise(&self, ctx: &QuestContext<'_>) -> Vec<(Facet, f32)>;

    /// How many quests to issue today.
    ///
    /// Default 5, adaptive 3–10 on completion rate.
    fn daily_count(&self, ctx: &QuestContext<'_>) -> usize;
}

/// What a generator gets to look at.
#[derive(Clone, Copy)]
pub struct QuestContext<'a> {
    /// The ghost doing the claiming.
    pub persona: &'a PersonaModel,
    /// Which version that is.
    pub version: PersonaVersion,
    /// The day being generated for.
    pub date: NaiveDate,
    /// Now.
    pub now: Timestamp,
    /// Entropy for nonces and holdout selection.
    ///
    /// A seam, not a convenience: holdout assignment must be reproducible in
    /// tests, or the property that makes the score meaningful cannot be tested.
    pub rng: &'a dyn Rng,
    /// What the local model can be trusted with.
    ///
    /// Drives graceful degradation. Below [`CapabilityTier::Baseline`] the
    /// generator emits fewer mechanical quests rather than bad hard ones
    /// (SPEC Q7).
    pub tier: CapabilityTier,
    /// Recent engagement, for the fatigue term.
    pub engagement: EngagementStats,
    /// The holdout policy in force.
    pub holdout: HoldoutPolicy,
}

impl core::fmt::Debug for QuestContext<'_> {
    /// Prints the scalar context, never the persona and never the RNG.
    ///
    /// `Rng` has no `Debug` bound on purpose: a rendering of an RNG is a
    /// rendering of its seed state, and the seed decides holdout assignment.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        todo!("print version, date, tier, engagement and holdout policy")
    }
}

/// How the user has been engaging.
#[derive(Debug, Clone, Copy, PartialEq, Default, Serialize, Deserialize)]
pub struct EngagementStats {
    /// Fraction of issued quests answered in the last 30 days.
    pub completion_rate: f32,
    /// Median seconds to answer.
    pub median_answer_seconds: f32,
    /// Consecutive days with at least one answer.
    pub streak_days: u32,
}

/// How quests are split between training and scoring.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct HoldoutPolicy {
    /// Fraction held out.
    ///
    /// 0.30 in steady state. Higher early on: at 5 quests a day a 30% holdout
    /// needs about 130 days to reach 200 scored quests, past the 60-day
    /// convergence floor. Raising it during the first month costs nothing —
    /// there is little to train on yet — and front-loads the evidence
    /// (SPEC Q8).
    pub fraction: f32,
    /// Fraction that are deliberately wrong. 0.05.
    pub decoy_fraction: f32,
    /// Seconds below which a verdict is flagged as suspiciously fast.
    ///
    /// Flagged in [`IntegritySignals`](ghostr_core::fidelity::IntegritySignals),
    /// never scored differently. Adjusting the score silently would hide the
    /// signal a reader needs in order to discount it.
    pub latency_floor_seconds: f32,
}

impl Default for HoldoutPolicy {
    fn default() -> Self {
        Self {
            fraction: 0.30,
            decoy_fraction: 0.05,
            latency_floor_seconds: 2.0,
        }
    }
}

/// Builds a quest's answer commitment.
///
/// `H_tag(QuestAnswer, quest_id || canonical(answer) || confidence || nonce)`.
///
/// # Errors
///
/// Returns [`Error::Core`](crate::Error::Core) if canonical encoding fails.
pub fn commit_answer(
    quest: &Quest,
    answer: &str,
    confidence: f32,
    nonce: &[u8; 32],
) -> crate::Result<ghostr_core::hash::Hash32> {
    todo!("canonically encode the answer and confidence, then tagged-hash with the nonce")
}
