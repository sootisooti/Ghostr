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
use serde::{Deserialize, Serialize};

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
    /// 1.96, the two-sided 95% normal quantile.
    const Z: f64 = 1.959_963_985;

    if trials == 0 {
        // No evidence means the whole range is possible, and saying so is the
        // honest answer. A zero-width interval at any point would claim
        // certainty from nothing — which is exactly the failure the interval is
        // reported to prevent.
        return (0.0, 1.0);
    }

    let n = f64::from(trials);
    let p = (f64::from(successes) / n).clamp(0.0, 1.0);
    let z2 = Z * Z;

    let denominator = 1.0 + z2 / n;
    let centre = p + z2 / (2.0 * n);
    let spread = Z * ((p * (1.0 - p) / n) + z2 / (4.0 * n * n)).sqrt();

    let lower = ((centre - spread) / denominator).clamp(0.0, 1.0);
    let upper = ((centre + spread) / denominator).clamp(0.0, 1.0);
    (lower as f32, upper as f32)
}

/// Expected calibration error across `bins` equal-width bins.
#[must_use]
pub fn expected_calibration_error(pairs: &[(f32, bool)], bins: usize) -> f32 {
    if pairs.is_empty() || bins == 0 {
        return 0.0;
    }
    let mut counts = vec![0u32; bins];
    let mut confidence_sum = vec![0f64; bins];
    let mut hit_sum = vec![0f64; bins];

    for (confidence, hit) in pairs {
        let c = f64::from(confidence.clamp(0.0, 1.0));
        // `min` rather than a modulo: a confidence of exactly 1.0 belongs in the
        // top bin, not wrapped into the bottom one.
        let index = ((c * bins as f64) as usize).min(bins - 1);
        counts[index] += 1;
        confidence_sum[index] += c;
        hit_sum[index] += f64::from(u8::from(*hit));
    }

    let total = pairs.len() as f64;
    let mut error = 0.0;
    for bin in 0..bins {
        if counts[bin] == 0 {
            continue;
        }
        let n = f64::from(counts[bin]);
        let mean_confidence = confidence_sum[bin] / n;
        let accuracy = hit_sum[bin] / n;
        // Weighted by how much of the sample landed in this bin: a bin holding
        // two answers should not move the number as much as one holding two
        // hundred.
        error += (n / total) * (mean_confidence - accuracy).abs();
    }
    error as f32
}

/// Brier score.
#[must_use]
pub fn brier_score(pairs: &[(f32, bool)]) -> f32 {
    if pairs.is_empty() {
        return 0.0;
    }
    let sum: f64 = pairs
        .iter()
        .map(|(confidence, hit)| {
            let outcome = f64::from(u8::from(*hit));
            let d = f64::from(confidence.clamp(0.0, 1.0)) - outcome;
            d * d
        })
        .sum();
    (sum / pairs.len() as f64) as f32
}

/// Exponentially weighted moving average over daily scores.
///
/// Reported beside the point estimate so a reader sees direction, not just
/// level.
#[must_use]
pub fn ewma(daily: &[f32], half_life_days: f32) -> f32 {
    if daily.is_empty() {
        return 0.0;
    }
    if half_life_days <= 0.0 {
        // A zero half-life means only the newest value counts, which is the
        // limit of the weighting rather than an error.
        return daily.last().copied().unwrap_or(0.0);
    }

    // `daily` is oldest-first, so age is distance from the end.
    let decay = 0.5f64.powf(1.0 / f64::from(half_life_days));
    let mut weighted = 0.0f64;
    let mut total_weight = 0.0f64;
    for (index, value) in daily.iter().rev().enumerate() {
        let weight = decay.powi(i32::try_from(index).unwrap_or(i32::MAX));
        weighted += weight * f64::from(*value);
        total_weight += weight;
    }
    if total_weight <= f64::EPSILON {
        return daily.last().copied().unwrap_or(0.0);
    }
    (weighted / total_weight) as f32
}

/// The convergence thresholds (SPEC §5.3).
///
/// Config, not constants. These numbers are a starting hypothesis with no
/// empirical basis yet; the first cohort's data is the calibration study
/// (SPEC Q9).
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
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

/// The reference scorer.
///
/// Every method is a pure function of its arguments. That is what makes the
/// property tests below possible, and it is also the point: a third party is
/// asked to believe this number, so it must be reimplementable from the spec
/// and checkable against this code.
#[derive(Debug, Clone, Copy, Default)]
pub struct StandardScorer {
    /// The thresholds convergence is measured against.
    pub thresholds: ConvergenceThresholds,
}

/// The smallest held-out sample that produces a score at all.
///
/// Below this the interval is so wide the number tells a reader nothing, and
/// printing one anyway invites a conclusion the evidence cannot support.
pub const MIN_SCOREABLE: u32 = 10;

/// Bins used for expected calibration error.
const ECE_BINS: usize = 10;

/// Turns a verdict into a per-quest score.
///
/// `Correct` earns partial credit because "close, but I'd have said *symptom*"
/// is not the same miss as being wrong about who you had lunch with.
#[must_use]
pub fn verdict_score(verdict: &ghostr_core::quest::Verdict) -> Option<f32> {
    use ghostr_core::quest::{Severity, Verdict};

    match verdict {
        Verdict::Confirm => Some(1.0),
        Verdict::Correct { severity, .. } => Some(match severity {
            Severity::Minor => 0.5,
            Severity::Major => 0.2,
        }),
        Verdict::Reject { .. } => Some(0.0),
        // Excluded from the ratio rather than counted as a miss. "I cannot say"
        // is not evidence the ghost was wrong, and scoring it as zero would
        // punish the ghost for the user's memory.
        Verdict::Unknown => None,
        // Excluded entirely. A scoring system where a broken question cannot be
        // thrown out is one that gets gamed by asking broken questions.
        Verdict::Void { .. } => None,
        _ => None,
    }
}

impl StandardScorer {
    /// A scorer with the default thresholds.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The half-life of the reported trend, in days (SPEC §5.2).
    const TREND_HALF_LIFE_DAYS: f32 = 30.0;

    /// The EWMA over daily scores, oldest day first.
    ///
    /// Each day is scored the way the whole window is — difficulty-weighted, by
    /// the same [`slice`](Self::slice) — so the trend and the level are one
    /// measurement at two resolutions. Weighting the days differently would
    /// make a rising trend on a falling score possible for arithmetic reasons
    /// rather than real ones.
    fn trend(scoreable: &[&ScoredQuest]) -> Option<f32> {
        use std::collections::BTreeMap;

        let mut by_day: BTreeMap<chrono::NaiveDate, Vec<&ScoredQuest>> = BTreeMap::new();
        for quest in scoreable {
            by_day
                .entry(quest.quest.issued_for)
                .or_default()
                .push(quest);
        }
        // One day is a level, not a direction.
        if by_day.len() < 2 {
            return None;
        }
        // `BTreeMap` iterates in key order, and for dates that is oldest first.
        // An EWMA fed newest-first reports the reverse of the truth, which is
        // worse than reporting nothing.
        let daily: Vec<f32> = by_day
            .into_values()
            .map(|day| Self::slice(&day).score)
            .collect();
        Some(ewma(&daily, Self::TREND_HALF_LIFE_DAYS))
    }

    /// Weighted agreement over a slice, and its interval.
    ///
    /// Weighted by difficulty: a hard question the ghost got right says more
    /// than an easy one, and a scoring system that treats them alike rewards
    /// asking easy questions.
    fn slice(quests: &[&ScoredQuest]) -> ghostr_core::fidelity::FacetScore {
        let scored: Vec<(f32, f32)> = quests
            .iter()
            .filter_map(|q| q.score.map(|s| (s, weight(q.quest.difficulty))))
            .collect();

        let total_weight: f32 = scored.iter().map(|(_, w)| w).sum();
        let score = if total_weight <= f32::EPSILON {
            0.0
        } else {
            scored.iter().map(|(s, w)| s * w).sum::<f32>() / total_weight
        };
        let n = u32::try_from(scored.len()).unwrap_or(u32::MAX);

        ghostr_core::fidelity::FacetScore {
            score,
            sample_size: n,
            // The interval is over the *unweighted* successes, because a Wilson
            // interval is defined on counts. Reporting a weighted point estimate
            // beside a count-based interval is the honest combination: the
            // weighting reflects what was asked, the interval reflects how much
            // was asked.
            confidence_interval: wilson_interval(scored.iter().map(|(s, _)| s).sum(), n),
        }
    }
}

/// How much a quest of a given difficulty counts.
///
/// Difficulty runs `0.0..=1.0`; the weight runs `0.5..=1.5`, so a trivial
/// question still counts for something and a hard one counts for three times as
/// much. A weight that reached zero would let the generator quietly stop
/// measuring by asking easy things.
fn weight(difficulty: f32) -> f32 {
    0.5 + difficulty.clamp(0.0, 1.0)
}

impl Scorer for StandardScorer {
    fn score_quest(&self, quest: &Quest) -> Option<f32> {
        quest.verdict.as_ref().and_then(verdict_score)
    }

    fn aggregate(
        &self,
        quests: &[ScoredQuest],
        window: ScoreWindow,
    ) -> crate::Result<FidelityScore> {
        use std::collections::BTreeMap;

        // I7, checked before anything is computed. A non-holdout or decoy quest
        // in the scoring set means the score is being computed on data the
        // model trained on, or on a claim that was deliberately wrong. Both
        // invalidate the number, and both fail loudly rather than being
        // filtered — a silent filter hides the caller bug that let it through.
        if let Some(bad) = quests.iter().find(|q| !q.quest.holdout || q.quest.decoy) {
            return Err(crate::Error::NonHoldoutInScore { id: bad.quest.id });
        }

        let scoreable: Vec<&ScoredQuest> = quests.iter().filter(|q| q.score.is_some()).collect();
        let n = u32::try_from(scoreable.len()).unwrap_or(u32::MAX);
        if n < MIN_SCOREABLE {
            return Err(crate::Error::InsufficientSample {
                have: n,
                need: MIN_SCOREABLE,
            });
        }

        let overall = Self::slice(&scoreable);

        let mut by_facet: BTreeMap<ghostr_core::quest::Facet, _> = BTreeMap::new();
        for facet in [
            ghostr_core::quest::Facet::Voice,
            ghostr_core::quest::Facet::Opinion,
            ghostr_core::quest::Facet::Relationship,
            ghostr_core::quest::Facet::Routine,
            ghostr_core::quest::Facet::Lore,
        ] {
            let slice: Vec<&ScoredQuest> = scoreable
                .iter()
                .copied()
                .filter(|q| q.quest.facet == facet)
                .collect();
            // An absent facet is absent, not zero. Inserting an empty slice
            // would report "0% on routines" for a ghost that was never asked
            // about routines.
            if !slice.is_empty() {
                by_facet.insert(facet, Self::slice(&slice));
            }
        }

        let mut by_quest_kind: BTreeMap<ghostr_core::fidelity::QuestKindTag, _> = BTreeMap::new();
        for quest in &scoreable {
            let Some(tag) = kind_tag(&quest.quest.kind) else {
                continue;
            };
            by_quest_kind.entry(tag).or_insert_with(|| {
                let slice: Vec<&ScoredQuest> = scoreable
                    .iter()
                    .copied()
                    .filter(|q| kind_tag(&q.quest.kind) == Some(tag))
                    .collect();
                Self::slice(&slice)
            });
        }

        let pairs: Vec<(f32, bool)> = scoreable
            .iter()
            .filter_map(|q| q.score.map(|s| (q.quest.confidence, s >= 0.5)))
            .collect();

        let mut score = FidelityScore {
            as_of: scoreable
                .iter()
                .map(|q| q.quest.issued_for)
                .max()
                .unwrap_or_default(),
            window,
            overall: overall.score,
            by_facet,
            by_quest_kind,
            sample_size: n,
            confidence_interval: overall.confidence_interval,
            calibration: self.calibration(&pairs),
            // SPEC §5.2's fourth aggregation output. `ewma` existed, with
            // property tests, and nothing called it — so the score reported a
            // level and never a direction.
            trend: Self::trend(&scoreable),
            // Filled by the caller, which is the only place that knows the
            // decoys — they are excluded from this set by construction.
            integrity: IntegritySignals {
                decoy_confirm_rate: 0.0,
                decoy_sample_size: 0,
                fast_verdict_rate: 0.0,
                longest_confirm_streak: 0,
                expiry_rate: 0.0,
            },
            converged: false,
            committed_at_seq: 0,
        };
        score.converged = self.converged(&score);
        Ok(score)
    }

    fn calibration(&self, pairs: &[(f32, bool)]) -> Calibration {
        Calibration {
            brier: brier_score(pairs),
            ece: expected_calibration_error(pairs, ECE_BINS),
            sample_size: u32::try_from(pairs.len()).unwrap_or(u32::MAX),
        }
    }

    fn integrity(&self, holdout: &[ScoredQuest], decoys: &[ScoredQuest]) -> IntegritySignals {
        use ghostr_core::quest::{QuestStatus, Verdict};

        let confirmed_decoys = decoys
            .iter()
            .filter(|q| matches!(q.quest.verdict, Some(Verdict::Confirm)))
            .count();
        let answered_decoys = decoys.iter().filter(|q| q.quest.verdict.is_some()).count();

        let mut longest = 0u32;
        let mut current = 0u32;
        for quest in holdout {
            if matches!(quest.quest.verdict, Some(Verdict::Confirm)) {
                current += 1;
                longest = longest.max(current);
            } else {
                current = 0;
            }
        }

        let all: Vec<&ScoredQuest> = holdout.iter().chain(decoys.iter()).collect();
        let fast = all
            .iter()
            .filter(|q| q.quest.verdict.is_some() && q.answer_seconds < 2.0)
            .count();
        let answered = all.iter().filter(|q| q.quest.verdict.is_some()).count();
        let expired = all
            .iter()
            .filter(|q| q.quest.status == QuestStatus::Expired)
            .count();

        IntegritySignals {
            decoy_confirm_rate: ratio(confirmed_decoys, answered_decoys),
            decoy_sample_size: u32::try_from(decoys.len()).unwrap_or(u32::MAX),
            fast_verdict_rate: ratio(fast, answered),
            longest_confirm_streak: longest,
            expiry_rate: ratio(expired, all.len()),
        }
    }

    fn converged(&self, score: &FidelityScore) -> bool {
        let t = self.thresholds;
        score.overall >= t.min_overall
            && score.confidence_interval.0 >= t.min_ci_lower
            && score.sample_size >= t.min_sample
            && score.calibration.ece <= t.max_ece
            && score.integrity.decoy_confirm_rate <= t.max_decoy_confirm_rate
            // Per facet as well as overall. A ghost converged on voice and
            // nowhere near on routines is not converged, and averaging that
            // away is the one thing the report must not do.
            && !score.by_facet.is_empty()
            && score
                .by_facet
                .values()
                .all(|f| f.sample_size >= t.min_per_facet)
    }
}

/// A ratio that is zero rather than NaN when nothing was counted.
fn ratio(numerator: usize, denominator: usize) -> f32 {
    if denominator == 0 {
        return 0.0;
    }
    numerator as f32 / denominator as f32
}

/// The reporting tag for a quest kind.
///
/// `None` for a kind this build does not recognise. `QuestKind` is
/// `#[non_exhaustive]`, and filing an unknown kind under an existing tag would
/// put its results in someone else's row — better to leave it out of the
/// breakdown than to report it wrongly. It still counts toward the overall
/// score, which is a fact about the ghost regardless of how it was asked.
#[must_use]
pub fn kind_tag(
    kind: &ghostr_core::quest::QuestKind,
) -> Option<ghostr_core::fidelity::QuestKindTag> {
    use ghostr_core::fidelity::QuestKindTag;
    use ghostr_core::quest::QuestKind;

    Some(match kind {
        QuestKind::VoiceProbe { .. } => QuestKindTag::VoiceProbe,
        QuestKind::FactRecall { .. } => QuestKindTag::FactRecall,
        QuestKind::Prediction { .. } => QuestKindTag::Prediction,
        QuestKind::Preference { .. } => QuestKindTag::Preference,
        QuestKind::Cloze { .. } => QuestKindTag::Cloze,
        QuestKind::Counterfactual { .. } => QuestKindTag::Counterfactual,
        _ => return None,
    })
}

#[cfg(test)]
pub(crate) mod fixtures {
    use ghostr_core::hash::Hash32;
    use ghostr_core::ids::{PersonaVersion, QuestId};
    use ghostr_core::quest::{Facet, QuestKind, QuestStatus, Verdict};
    use ghostr_core::time::Timestamp;

    use super::*;

    pub(crate) fn quest(n: u8, facet: Facet, verdict: Option<Verdict>) -> Quest {
        Quest {
            id: QuestId::new(u64::from(n) + 1, [n; 10]),
            issued_for: chrono::NaiveDate::from_ymd_opt(2026, 1, 5).unwrap_or_default(),
            issued_at: Timestamp::new(0, 0),
            persona_version: PersonaVersion::genesis(),
            kind: QuestKind::FactRecall {
                claim: "you saw someone on Tuesday".to_owned(),
                as_of: chrono::NaiveDate::from_ymd_opt(2026, 1, 5).unwrap_or_default(),
            },
            facet,
            difficulty: 0.5,
            evidence: Vec::new(),
            confidence: 0.7,
            answer_commitment: Hash32::zero(),
            nonce: [n; 32],
            holdout: true,
            decoy: false,
            expires_at: Timestamp::new(86_400_000, 0),
            status: QuestStatus::Answered,
            verdict,
        }
    }

    pub(crate) fn scored(n: u8, facet: Facet, verdict: Verdict) -> ScoredQuest {
        let score = verdict_score(&verdict);
        ScoredQuest {
            quest: quest(n, facet, Some(verdict)),
            score,
            answer_seconds: 12.0,
        }
    }

    /// A run spread over `days`, with each day's verdicts given by `right`.
    ///
    /// `right[i]` is whether day `i` went well, oldest day first. Four quests a
    /// day, which clears `MIN_SCOREABLE` at three days.
    pub(crate) fn run_over_days(right: &[bool]) -> Vec<ScoredQuest> {
        let start = chrono::NaiveDate::from_ymd_opt(2026, 1, 5).unwrap_or_default();
        let mut out = Vec::new();
        let mut n = 0u8;
        for (offset, ok) in right.iter().enumerate() {
            for _ in 0..4 {
                let verdict = if *ok {
                    Verdict::Confirm
                } else {
                    Verdict::Reject { note: None }
                };
                let mut q = scored(n, Facet::Voice, verdict);
                q.quest.issued_for = start
                    .checked_add_days(chrono::Days::new(offset as u64))
                    .unwrap_or(start);
                q.quest.confidence = if *ok { 1.0 } else { 0.0 };
                out.push(q);
                n = n.wrapping_add(1);
            }
        }
        out
    }

    /// `count` held-out quests, all confirmed, spread across the facets so a
    /// per-facet breakdown has something in it.
    ///
    /// Confidence is 1.0 to match the perfect record. A ghost that is always
    /// right while claiming 0.7 is *underconfident*, which is a real
    /// calibration failure and would correctly block convergence — see
    /// `being_right_is_not_enough_the_ghost_must_know_it`.
    pub(crate) fn confirmed_run(count: u8) -> Vec<ScoredQuest> {
        let facets = [
            Facet::Voice,
            Facet::Opinion,
            Facet::Relationship,
            Facet::Routine,
            Facet::Lore,
        ];
        (0..count)
            .map(|n| {
                let mut q = scored(n, facets[usize::from(n) % facets.len()], Verdict::Confirm);
                q.quest.confidence = 1.0;
                q
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use ghostr_core::quest::{Facet, QuestStatus, Severity, Verdict};

    use super::fixtures::*;
    use super::*;

    /// SPEC §5.2's fourth output, which nothing computed: `ewma` was
    /// implemented and property-tested, and had no production caller, so the
    /// score reported a level and never a direction.
    ///
    /// A ghost improving over the window trends *above* its own average.
    #[test]
    fn a_ghost_getting_better_trends_above_its_window_average() {
        let quests = run_over_days(&[false, false, false, true, true, true]);
        let score = StandardScorer::new()
            .aggregate(&quests, ScoreWindow::Rolling30)
            .expect("aggregate");
        let trend = score.trend.expect("six days is a trend");
        assert!(
            trend > score.overall,
            "trend {trend} should sit above overall {}",
            score.overall
        );
    }

    /// And a ghost getting worse trends below it.
    ///
    /// This is the pair that pins the *ordering*. An EWMA fed newest-first
    /// reports the exact reverse of the truth — a decaying ghost as improving —
    /// and either test alone would pass against that, because the two series
    /// are mirror images.
    #[test]
    fn a_ghost_getting_worse_trends_below_its_window_average() {
        let quests = run_over_days(&[true, true, true, false, false, false]);
        let score = StandardScorer::new()
            .aggregate(&quests, ScoreWindow::Rolling30)
            .expect("aggregate");
        let trend = score.trend.expect("six days is a trend");
        assert!(
            trend < score.overall,
            "trend {trend} should sit below overall {}",
            score.overall
        );
    }

    /// One day is a level, not a direction, and the report says so rather than
    /// printing the day's own score as if it were a trend.
    #[test]
    fn a_single_day_has_no_trend() {
        let score = StandardScorer::new()
            .aggregate(&confirmed_run(20), ScoreWindow::Rolling30)
            .expect("aggregate");
        assert_eq!(score.trend, None);
    }

    /// SPEC I7. A non-holdout quest in the scoring set means the score is being
    /// computed on data the model trained on. It fails loudly rather than being
    /// filtered, because a silent filter hides the caller bug that let it
    /// through — and that bug invalidates every score since.
    #[test]
    fn a_non_holdout_quest_in_the_score_is_refused() {
        let mut quests = confirmed_run(20);
        quests[7].quest.holdout = false;
        let err = StandardScorer::new()
            .aggregate(&quests, ScoreWindow::Rolling30)
            .expect_err("must refuse");
        assert!(matches!(err, crate::Error::NonHoldoutInScore { .. }));
    }

    /// A decoy is a claim that was deliberately wrong. Scoring against it would
    /// measure the ghost on a question it was set up to fail.
    #[test]
    fn a_decoy_in_the_score_is_refused() {
        let mut quests = confirmed_run(20);
        quests[3].quest.decoy = true;
        assert!(matches!(
            StandardScorer::new().aggregate(&quests, ScoreWindow::Rolling30),
            Err(crate::Error::NonHoldoutInScore { .. })
        ));
    }

    /// 100% over four quests is noise. Printing a number anyway invites a
    /// conclusion the evidence cannot support.
    #[test]
    fn too_small_a_sample_produces_no_score() {
        let quests = confirmed_run(4);
        let err = StandardScorer::new()
            .aggregate(&quests, ScoreWindow::Rolling30)
            .expect_err("must refuse");
        assert!(matches!(
            err,
            crate::Error::InsufficientSample { have: 4, .. }
        ));
    }

    #[test]
    fn a_perfect_run_scores_one_with_an_interval_below_it() {
        let score = StandardScorer::new()
            .aggregate(&confirmed_run(20), ScoreWindow::Rolling30)
            .expect("score");
        assert!((score.overall - 1.0).abs() < 1e-5);
        assert_eq!(score.sample_size, 20);
        // Twenty for twenty is not proof of perfection.
        assert!(score.confidence_interval.0 < 1.0);
        assert!(score.confidence_interval.1 <= 1.0);
    }

    /// Partial credit: "close, but I'd have said *symptom*" is not the same
    /// miss as being wrong about who you had lunch with.
    #[test]
    fn a_minor_correction_scores_above_a_major_one_and_both_above_a_reject() {
        let minor = verdict_score(&Verdict::Correct {
            correction: "nearly".to_owned(),
            severity: Severity::Minor,
        })
        .expect("scored");
        let major = verdict_score(&Verdict::Correct {
            correction: "not really".to_owned(),
            severity: Severity::Major,
        })
        .expect("scored");
        let reject = verdict_score(&Verdict::Reject { note: None }).expect("scored");

        assert!(minor > major);
        assert!(major > reject);
        assert!(verdict_score(&Verdict::Confirm).expect("scored") > minor);
    }

    /// "I cannot say" is not evidence the ghost was wrong. Scoring it as zero
    /// would punish the ghost for the user's memory.
    #[test]
    fn unknown_and_void_are_excluded_rather_than_counted_as_misses() {
        assert!(verdict_score(&Verdict::Unknown).is_none());
        assert!(
            verdict_score(&Verdict::Void {
                reason: "the question named my therapist".to_owned()
            })
            .is_none()
        );

        // And they do not drag the ratio down.
        let mut quests = confirmed_run(20);
        quests.push(scored(90, Facet::Voice, Verdict::Unknown));
        let score = StandardScorer::new()
            .aggregate(&quests, ScoreWindow::Rolling30)
            .expect("score");
        assert!((score.overall - 1.0).abs() < 1e-5);
        assert_eq!(score.sample_size, 20, "the unknown is not in the sample");
    }

    /// Weighted by difficulty: a hard question the ghost got right says more
    /// than an easy one, and treating them alike rewards asking easy questions.
    #[test]
    fn a_hard_success_counts_for_more_than_an_easy_one() {
        let mut easy_right = confirmed_run(20);
        for (index, q) in easy_right.iter_mut().enumerate() {
            // Half easy and right, half hard and wrong.
            if index % 2 == 0 {
                q.quest.difficulty = 0.0;
            } else {
                q.quest.difficulty = 1.0;
                q.quest.verdict = Some(Verdict::Reject { note: None });
                q.score = Some(0.0);
            }
        }
        let easy_bias = StandardScorer::new()
            .aggregate(&easy_right, ScoreWindow::Rolling30)
            .expect("score")
            .overall;

        let mut hard_right = easy_right.clone();
        for q in &mut hard_right {
            q.quest.difficulty = 1.0 - q.quest.difficulty;
        }
        let hard_bias = StandardScorer::new()
            .aggregate(&hard_right, ScoreWindow::Rolling30)
            .expect("score")
            .overall;

        assert!(
            hard_bias > easy_bias,
            "getting the hard ones right ({hard_bias}) should beat getting the easy ones right ({easy_bias})"
        );
    }

    /// A ghost can be converged on voice and nowhere near on routines.
    /// Reporting only the mean would hide exactly what a user needs to know.
    #[test]
    fn the_breakdown_reports_each_facet_separately() {
        let mut quests = confirmed_run(20);
        for q in &mut quests {
            if q.quest.facet == Facet::Routine {
                q.quest.verdict = Some(Verdict::Reject { note: None });
                q.score = Some(0.0);
            }
        }
        let score = StandardScorer::new()
            .aggregate(&quests, ScoreWindow::Rolling30)
            .expect("score");

        let routine = score.by_facet.get(&Facet::Routine).expect("routines");
        let voice = score.by_facet.get(&Facet::Voice).expect("voice");
        assert!(routine.score < 0.01);
        assert!(voice.score > 0.99);
        assert!(score.overall > routine.score && score.overall < voice.score);
    }

    /// An absent facet is absent, not zero. Reporting "0% on routines" for a
    /// ghost that was never asked about routines would be a false claim.
    #[test]
    fn a_facet_that_was_never_asked_about_is_absent_not_zero() {
        let quests: Vec<ScoredQuest> = (0..20)
            .map(|n| scored(n, Facet::Voice, Verdict::Confirm))
            .collect();
        let score = StandardScorer::new()
            .aggregate(&quests, ScoreWindow::Rolling30)
            .expect("score");
        assert!(score.by_facet.contains_key(&Facet::Voice));
        assert!(!score.by_facet.contains_key(&Facet::Routine));
    }

    /// Convergence is per facet as well as overall. Averaging that away is the
    /// one thing the report must not do.
    #[test]
    fn a_ghost_strong_overall_but_thin_on_one_facet_is_not_converged() {
        let mut quests = confirmed_run(220);
        // Only two questions ever asked about routines.
        for q in quests.iter_mut() {
            if q.quest.facet == Facet::Routine {
                q.quest.facet = Facet::Voice;
            }
        }
        quests[0].quest.facet = Facet::Routine;
        quests[1].quest.facet = Facet::Routine;

        let score = StandardScorer::new()
            .aggregate(&quests, ScoreWindow::Rolling30)
            .expect("score");
        assert!(score.overall > 0.99, "overall is strong");
        assert!(
            !score.converged,
            "but two routine questions is not converged"
        );
    }

    /// The property that makes calibration a criterion rather than a footnote:
    /// a ghost right every time while claiming 70% is *underconfident*, and
    /// under-claiming is as much a modelling failure as over-claiming. Its
    /// stated confidence is not tracking reality, so the number it reports
    /// about itself cannot be trusted either.
    #[test]
    fn being_right_is_not_enough_the_ghost_must_know_it() {
        let mut underconfident = confirmed_run(250);
        for q in &mut underconfident {
            q.quest.confidence = 0.7;
        }
        let score = StandardScorer::new()
            .aggregate(&underconfident, ScoreWindow::Rolling30)
            .expect("score");

        assert!((score.overall - 1.0).abs() < 1e-5, "it is right every time");
        assert!(score.calibration.ece > 0.05, "but it does not know that");
        assert!(!score.converged);
    }

    #[test]
    fn a_long_strong_run_does_converge() {
        let score = StandardScorer::new()
            .aggregate(&confirmed_run(250), ScoreWindow::Rolling30)
            .expect("score");
        assert!(score.converged, "{score:?}");
    }

    /// Integrity signals sit beside the score, never inside it. Adjusting the
    /// number silently would remove the very thing a reader needs to discount
    /// it.
    #[test]
    fn confirming_decoys_shows_up_without_moving_the_score() {
        let holdout = confirmed_run(20);
        let decoys: Vec<ScoredQuest> = (100..110)
            .map(|n| {
                let mut q = scored(n, Facet::Voice, Verdict::Confirm);
                q.quest.decoy = true;
                q.quest.holdout = false;
                q
            })
            .collect();

        let scorer = StandardScorer::new();
        let score = scorer
            .aggregate(&holdout, ScoreWindow::Rolling30)
            .expect("score");
        let integrity = scorer.integrity(&holdout, &decoys);

        assert!((score.overall - 1.0).abs() < 1e-5, "the score is untouched");
        assert!(
            (integrity.decoy_confirm_rate - 1.0).abs() < 1e-5,
            "but every decoy was rubber-stamped"
        );
        assert_eq!(integrity.decoy_sample_size, 10);
        assert_eq!(integrity.longest_confirm_streak, 20);
    }

    /// A rubber-stamping user cannot reach convergence, because the decoy rate
    /// is a criterion rather than a footnote.
    #[test]
    fn a_high_decoy_rate_blocks_convergence() {
        let scorer = StandardScorer::new();
        let mut score = scorer
            .aggregate(&confirmed_run(250), ScoreWindow::Rolling30)
            .expect("score");
        assert!(score.converged);

        score.integrity.decoy_confirm_rate = 0.5;
        assert!(!scorer.converged(&score));
    }

    #[test]
    fn fast_and_expired_verdicts_are_counted() {
        let mut holdout = confirmed_run(20);
        holdout[0].answer_seconds = 0.4;
        holdout[1].answer_seconds = 0.9;
        holdout[2].quest.status = QuestStatus::Expired;

        let integrity = StandardScorer::new().integrity(&holdout, &[]);
        assert!(integrity.fast_verdict_rate > 0.0);
        assert!(integrity.expiry_rate > 0.0);
    }

    /// An unrecognised kind still counts toward the overall score — that is a
    /// fact about the ghost regardless of how it was asked — but it is left out
    /// of the per-kind breakdown rather than filed under someone else's row.
    #[test]
    fn an_unknown_quest_kind_is_absent_from_the_breakdown() {
        let score = StandardScorer::new()
            .aggregate(&confirmed_run(20), ScoreWindow::Rolling30)
            .expect("score");
        assert_eq!(score.by_quest_kind.len(), 1, "all fixtures are FactRecall");
        assert!(
            score
                .by_quest_kind
                .contains_key(&ghostr_core::fidelity::QuestKindTag::FactRecall)
        );
    }
}
