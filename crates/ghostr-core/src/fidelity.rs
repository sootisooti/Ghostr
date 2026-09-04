//! [`FidelityScore`] — the product claim, and the numbers that keep it honest.
//!
//! The score is never a bare percentage. It always travels with its sample size,
//! its confidence interval, and its integrity signals, because 100% over four
//! quests is noise and 92% with a 30% decoy-confirm rate is a lie (SPEC §3.7).

use std::collections::BTreeMap;

use chrono::NaiveDate;
use serde::{Deserialize, Serialize};

use crate::quest::Facet;

/// Agreement between ghost and user over a window.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FidelityScore {
    /// The day this was computed for.
    pub as_of: NaiveDate,
    /// Which window it covers.
    pub window: ScoreWindow,
    /// Weighted agreement, in `0.0..=1.0`.
    pub overall: f32,
    /// Per-facet breakdown.
    ///
    /// A ghost can be converged on voice and nowhere near on routines. Reporting
    /// only the mean would hide exactly the thing a user needs to know.
    pub by_facet: BTreeMap<Facet, FacetScore>,
    /// Per-quest-kind breakdown.
    pub by_quest_kind: BTreeMap<QuestKindTag, FacetScore>,
    /// Held-out, non-decoy, non-void quests in the window.
    pub sample_size: u32,
    /// Wilson score interval at 95%.
    ///
    /// Not a naive proportion: the sample is small and bounded at 1.0, which is
    /// precisely where a normal approximation misleads.
    pub confidence_interval: (f32, f32),
    /// How well the ghost's confidence tracks its accuracy.
    pub calibration: Calibration,
    /// 30-day EWMA of the daily scores, reported beside the point estimate
    /// (SPEC §5.2).
    ///
    /// `None` when the window holds a single day: a trend needs somewhere to
    /// have come from, and one point is a level rather than a direction.
    ///
    /// The whole reason the report is not a bare number. A user watching their
    /// ghost cannot tell an improving 0.72 from a decaying one, and which of
    /// those it is matters more than the 0.72.
    pub trend: Option<f32>,
    /// Signals that the score may not mean what it says.
    pub integrity: IntegritySignals,
    /// Whether every convergence criterion is met (SPEC §5.3).
    pub converged: bool,
    /// The chain `seq` this was computed at.
    ///
    /// Ties the number to anchored evidence: a published score points at a
    /// commitment a third party can check (SPEC §9.4).
    pub committed_at_seq: u64,
}

/// One slice of a [`FidelityScore`].
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct FacetScore {
    /// Weighted agreement for this slice.
    pub score: f32,
    /// Quests in this slice.
    pub sample_size: u32,
    /// Wilson interval for this slice.
    pub confidence_interval: (f32, f32),
}

/// Which period a score covers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ScoreWindow {
    /// The last 30 days.
    Rolling30,
    /// The last 90 days.
    Rolling90,
    /// Everything.
    AllTime,
}

/// A [`QuestKind`](crate::quest::QuestKind) discriminant, for score breakdowns.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum QuestKindTag {
    /// [`QuestKind::VoiceProbe`](crate::quest::QuestKind::VoiceProbe).
    VoiceProbe,
    /// [`QuestKind::FactRecall`](crate::quest::QuestKind::FactRecall).
    FactRecall,
    /// [`QuestKind::Prediction`](crate::quest::QuestKind::Prediction).
    Prediction,
    /// [`QuestKind::Preference`](crate::quest::QuestKind::Preference).
    Preference,
    /// [`QuestKind::Cloze`](crate::quest::QuestKind::Cloze).
    Cloze,
    /// [`QuestKind::Counterfactual`](crate::quest::QuestKind::Counterfactual).
    Counterfactual,
}

/// How well the ghost's stated confidence tracks its actual accuracy.
///
/// A ghost that is right 70% of the time and knows it is more useful than one
/// that is right 75% and always claims 95%.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Calibration {
    /// Brier score over `(confidence, outcome)` pairs. Lower is better.
    pub brier: f32,
    /// Expected calibration error across ten bins. Lower is better.
    pub ece: f32,
    /// Pairs the calibration was computed from.
    pub sample_size: u32,
}

/// Signals that a score may not mean what it appears to.
///
/// Surfaced alongside the score rather than folded into it. Adjusting the number
/// silently would hide the very thing a reader needs in order to discount it.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct IntegritySignals {
    /// Fraction of decoy quests the user confirmed. Should be near zero.
    pub decoy_confirm_rate: f32,
    /// Decoys presented in the window.
    pub decoy_sample_size: u32,
    /// Fraction of verdicts returned faster than a plausible read time.
    pub fast_verdict_rate: f32,
    /// Longest run of consecutive confirmations.
    pub longest_confirm_streak: u32,
    /// Fraction of issued quests that expired unanswered.
    pub expiry_rate: f32,
}
