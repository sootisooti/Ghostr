//! Property tests over the fidelity score.
//!
//! CLAUDE.md §6 asks for pure property tests here — monotonicity, interval
//! bounds, calibration — and the reason is the product claim. The score is the
//! thing a third party is asked to believe, so the properties it must satisfy
//! are worth stating as properties rather than as a handful of examples
//! somebody happened to pick.
//!
//! Everything below is a pure function of its arguments. No store, no model, no
//! clock.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use ghostr_quests::score::{brier_score, ewma, expected_calibration_error, wilson_interval};
use proptest::prelude::*;

/// Confidence/outcome pairs.
fn pairs(max: usize) -> impl Strategy<Value = Vec<(f32, bool)>> {
    proptest::collection::vec((0.0f32..=1.0, any::<bool>()), 0..=max)
}

proptest! {
    /// An interval that left `0.0..=1.0` would be reporting an impossible
    /// accuracy, and the whole reason a Wilson interval is used here rather
    /// than a normal approximation is that the latter does exactly that near
    /// the extremes.
    #[test]
    fn a_wilson_interval_stays_inside_the_unit_range(
        trials in 0u32..500,
        fraction in 0.0f32..=1.0,
    ) {
        let successes = fraction * trials as f32;
        let (lower, upper) = wilson_interval(successes, trials);
        prop_assert!((0.0..=1.0).contains(&lower), "lower {lower}");
        prop_assert!((0.0..=1.0).contains(&upper), "upper {upper}");
        prop_assert!(lower <= upper, "{lower} > {upper}");
    }

    /// The interval must contain the point estimate. An interval that excluded
    /// its own centre would make the reported number and the reported
    /// uncertainty contradict each other.
    #[test]
    fn the_interval_contains_the_point_estimate(
        trials in 1u32..500,
        fraction in 0.0f32..=1.0,
    ) {
        let successes = fraction * trials as f32;
        let p = successes / trials as f32;
        let (lower, upper) = wilson_interval(successes, trials);
        prop_assert!(lower <= p + 1e-5, "{lower} > {p}");
        prop_assert!(upper >= p - 1e-5, "{upper} < {p}");
    }

    /// More evidence narrows the interval. If it did not, sample size would
    /// carry no information and reporting it beside the score would be
    /// decoration.
    #[test]
    fn more_evidence_narrows_the_interval(fraction in 0.1f32..=0.9) {
        let width = |n: u32| {
            let (lo, hi) = wilson_interval(fraction * n as f32, n);
            hi - lo
        };
        prop_assert!(width(200) < width(20), "200 was not tighter than 20");
        prop_assert!(width(20) < width(5), "20 was not tighter than 5");
    }

    /// A perfect record does not produce a zero-width interval at 1.0. Ten out
    /// of ten is not proof of perfection, and an interval that said so would be
    /// the single most misleading number the product could print.
    #[test]
    fn a_perfect_small_sample_still_admits_doubt(trials in 1u32..40) {
        let (lower, upper) = wilson_interval(trials as f32, trials);
        prop_assert!(upper <= 1.0);
        prop_assert!(
            lower < 0.999,
            "{trials}/{trials} claimed a lower bound of {lower}"
        );
    }

    /// And the same at the bottom: zero out of ten is not proof of uselessness.
    #[test]
    fn a_perfect_failure_still_admits_doubt(trials in 1u32..40) {
        let (lower, upper) = wilson_interval(0.0, trials);
        prop_assert!(lower >= 0.0);
        prop_assert!(upper > 0.001, "0/{trials} claimed an upper bound of {upper}");
    }

    /// No evidence means the whole range is possible. Any narrower answer would
    /// claim certainty from nothing.
    #[test]
    fn an_empty_sample_admits_everything(fraction in 0.0f32..=1.0) {
        prop_assert_eq!(wilson_interval(fraction, 0), (0.0, 1.0));
    }

    /// Brier is a squared error, so it is bounded and never negative.
    #[test]
    fn brier_stays_in_range(pairs in pairs(200)) {
        let b = brier_score(&pairs);
        prop_assert!((0.0..=1.0).contains(&b), "brier {b}");
    }

    /// A ghost that is always right and always says so scores zero — the
    /// definition of the measure, and worth pinning because an inverted sign
    /// would make a worse ghost look better.
    #[test]
    fn perfect_confidence_on_perfect_outcomes_is_zero(n in 1usize..100) {
        let perfect: Vec<(f32, bool)> = std::iter::repeat_n((1.0, true), n).collect();
        prop_assert!(brier_score(&perfect) < 1e-6);
    }

    /// And one that is always wrong while claiming certainty scores the worst
    /// possible value.
    #[test]
    fn certain_and_wrong_is_the_worst_brier(n in 1usize..100) {
        let awful: Vec<(f32, bool)> = std::iter::repeat_n((1.0, false), n).collect();
        prop_assert!((brier_score(&awful) - 1.0).abs() < 1e-6);
    }

    /// Expected calibration error is a weighted mean of absolute gaps, so it is
    /// bounded the same way.
    #[test]
    fn ece_stays_in_range(pairs in pairs(200)) {
        let e = expected_calibration_error(&pairs, 10);
        prop_assert!((0.0..=1.0).contains(&e), "ece {e}");
    }

    /// A ghost whose confidence matches its accuracy is calibrated, whatever
    /// its accuracy. This is the property that makes calibration worth
    /// reporting separately from the score: being right 70% of the time and
    /// knowing it is a different thing from being right 70% of the time.
    #[test]
    fn matching_confidence_to_accuracy_is_well_calibrated(hits in 1usize..50) {
        let misses = hits;
        // Half the answers right, and a stated confidence of exactly 0.5.
        let mut sample: Vec<(f32, bool)> = std::iter::repeat_n((0.5, true), hits).collect();
        sample.extend(std::iter::repeat_n((0.5, false), misses));
        prop_assert!(
            expected_calibration_error(&sample, 10) < 1e-5,
            "a perfectly calibrated sample scored {}",
            expected_calibration_error(&sample, 10)
        );
    }

    /// Overconfidence shows up as error. A ghost that always claims certainty
    /// and is right half the time is exactly the failure this measure exists to
    /// surface.
    #[test]
    fn overconfidence_is_penalised(n in 5usize..50) {
        let mut overconfident: Vec<(f32, bool)> = std::iter::repeat_n((1.0, true), n).collect();
        overconfident.extend(std::iter::repeat_n((1.0, false), n));
        let honest: Vec<(f32, bool)> = overconfident
            .iter()
            .map(|(_, hit)| (0.5, *hit))
            .collect();

        prop_assert!(
            expected_calibration_error(&overconfident, 10)
                > expected_calibration_error(&honest, 10)
        );
    }

    /// A confidence of exactly 1.0 belongs in the top bin, not wrapped into the
    /// bottom one — an off-by-one that would report a perfectly calibrated
    /// certain ghost as maximally miscalibrated.
    #[test]
    fn a_confidence_of_exactly_one_lands_in_the_top_bin(n in 1usize..50) {
        let certain_and_right: Vec<(f32, bool)> = std::iter::repeat_n((1.0, true), n).collect();
        prop_assert!(expected_calibration_error(&certain_and_right, 10) < 1e-5);
    }

    /// An average must sit within the range of what it averages.
    #[test]
    fn ewma_stays_within_the_series(
        series in proptest::collection::vec(0.0f32..=1.0, 1..100),
        half_life in 0.5f32..30.0,
    ) {
        let value = ewma(&series, half_life);
        let min = series.iter().copied().fold(f32::INFINITY, f32::min);
        let max = series.iter().copied().fold(f32::NEG_INFINITY, f32::max);
        prop_assert!(value >= min - 1e-5, "{value} below {min}");
        prop_assert!(value <= max + 1e-5, "{value} above {max}");
    }

    /// A flat series averages to its own value, whatever the half-life.
    #[test]
    fn a_flat_series_averages_to_itself(
        value in 0.0f32..=1.0,
        n in 1usize..50,
        half_life in 0.5f32..30.0,
    ) {
        let series: Vec<f32> = std::iter::repeat_n(value, n).collect();
        prop_assert!((ewma(&series, half_life) - value).abs() < 1e-4);
    }

    /// Recent values weigh more. Without this the "direction" the EWMA is
    /// reported for would be indistinguishable from the level.
    #[test]
    fn ewma_leans_toward_the_recent_end(n in 4usize..40) {
        // Rising series: the weighted mean should sit above the plain mean.
        let rising: Vec<f32> = (0..n).map(|i| i as f32 / n as f32).collect();
        let plain = rising.iter().sum::<f32>() / n as f32;
        prop_assert!(
            ewma(&rising, 3.0) > plain,
            "a rising series averaged to {} against a plain mean of {plain}",
            ewma(&rising, 3.0)
        );
    }
}
