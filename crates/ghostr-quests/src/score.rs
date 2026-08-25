//! Fidelity scoring (SPEC §5).
//!
//! Pure math. No store, no model, no clock, no I/O. The fidelity number is what
//! a third party is asked to believe, so it has to be reimplementable from the
//! spec and checkable against this implementation.
//!
//! # Per-quest scores
//!
//! ```text
//! Confirm                  => 1.0
//! Correct { Minor }        => 0.5
//! Correct { Major }        => 0.2
//! Reject                   => 0.0
//! Unknown                  => excluded from the ratio, counted separately
//! Void                     => excluded entirely
//! ```
//!
//! `Correct` earns partial credit because "close, but I'd have said *symptom*"
//! is not the same miss as being wrong about who you had lunch with.

use ghostr_core::fidelity::{Calibration, FidelityScore, IntegritySignals, ScoreWindow};
use ghostr_core::quest::Quest;

/// Computes fidelity scores.
///
/// Every method is a pure function of its arguments, which is what makes the
/// property tests possible: monotonicity, interval bounds, and calibration
/// behaviour on synthetic distributions.
pub trait Scorer: Send + Sync {
    /// Scores one answered quest.
    fn score_quest(&self, quest: &Quest) -> Option<f32>;

    /// Aggregates over a window.
    ///
    /// Callers must pass **only** held-out, non-decoy quests. Implementations
    /// must verify that and return
    /// [`Error::NonHoldoutInScore`](crate::Error::NonHoldoutInScore) rather than
    /// filtering: silently dropping a non-holdout quest would hide the caller
    /// bug that let it through, and that bug invalidates every score since
    /// (SPEC I7).
    ///
    /// # Errors
    ///
    /// Returns [`Error::InsufficientSample`](crate::Error::InsufficientSample)
    /// or [`Error::NonHoldoutInScore`](crate::Error::NonHoldoutInScore).
    fn aggregate(
        &self,
        quests: &[ScoredQuest],
        window: ScoreWindow,
    ) -> crate::Result<FidelityScore>;

    /// Brier score and expected calibration error over `(confidence, hit)` pairs.
    ///
    /// A ghost right 70% of the time that knows it is more useful than one right
    /// 75% that always claims 95%.
    fn calibration(&self, pairs: &[(f32, bool)]) -> Calibration;

    /// Integrity signals over a window.
    ///
    /// Reported beside the score, never folded into it. Adjusting the number
    /// silently would remove the very thing a reader needs in order to discount
    /// it.
    fn integrity(&self, holdout: &[ScoredQuest], decoys: &[ScoredQuest]) -> IntegritySignals;

    /// Whether every convergence criterion is met (SPEC §5.3).
    ///
    /// Per-facet as well as overall: a ghost can be converged on voice and
    /// nowhere near on routines, and averaging that away is the one thing the
    /// report must not do.
    fn converged(&self, score: &FidelityScore) -> bool;
}

/// A quest with its computed score.
#[derive(Debug, Clone, PartialEq)]
pub struct ScoredQuest {
    /// The quest.
    pub quest: Quest,
    /// Its per-quest score, or `None` for `Unknown` and `Void`.
    pub score: Option<f32>,
    /// Seconds the user took to answer.
    pub answer_seconds: f32,
}

/// Wilson score interval at 95%.
///
/// Not a naive normal approximation: the sample is small and bounded at 1.0,
/// which is exactly where the normal approximation produces intervals that
/// extend past 100% or collapse to zero width at the extremes.
#[must_use]
pub fn wilson_interval(successes: f32, trials: u32) -> (f32, f32) {
    todo!("Wilson score interval with continuity handling for the n=0 case")
}

/// Expected calibration error across `bins` equal-width bins.
#[must_use]
pub fn expected_calibration_error(pairs: &[(f32, bool)], bins: usize) -> f32 {
    todo!("bin by confidence, take the weighted mean absolute gap")
}

/// Brier score.
#[must_use]
pub fn brier_score(pairs: &[(f32, bool)]) -> f32 {
    todo!("mean squared difference between confidence and outcome")
}

/// Exponentially weighted moving average over daily scores.
///
/// Reported beside the point estimate so a reader sees direction, not just
/// level.
#[must_use]
pub fn ewma(daily: &[f32], half_life_days: f32) -> f32 {
    todo!("exponentially weight the series by the given half-life")
}

/// The convergence thresholds (SPEC §5.3).
///
/// Config, not constants. These numbers are a starting hypothesis with no
/// empirical basis yet; the first cohort's data is the calibration study
/// (SPEC Q9).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ConvergenceThresholds {
    /// Minimum overall score.
    pub min_overall: f32,
    /// Minimum lower bound of the confidence interval.
    pub min_ci_lower: f32,
    /// Minimum held-out sample.
    pub min_sample: u32,
    /// Minimum distinct sealed days.
    pub min_days: u32,
    /// Minimum scored quests per facet.
    pub min_per_facet: u32,
    /// Maximum expected calibration error.
    pub max_ece: f32,
    /// Maximum tolerated decoy confirm rate.
    pub max_decoy_confirm_rate: f32,
}

impl Default for ConvergenceThresholds {
    fn default() -> Self {
        Self {
            min_overall: 0.85,
            min_ci_lower: 0.80,
            min_sample: 200,
            min_days: 60,
            min_per_facet: 20,
            max_ece: 0.05,
            max_decoy_confirm_rate: 0.10,
        }
    }
}
