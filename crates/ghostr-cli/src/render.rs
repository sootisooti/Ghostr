//! Turning engine output into terminal text.
//!
//! Every renderer here follows one rule: **never print a number without what
//! qualifies it.** A bare 92% invites a conclusion the sample does not support,
//! and this project's entire claim rests on the number being trustworthy.

use ghostr_engine::types::{Amendment, FidelityScore, Footage, PersonaDiff, VerificationReport};

/// Renders a fidelity score.
///
/// Always alongside its sample size, confidence interval, and decoy confirm
/// rate. 100% over four quests is noise, and 92% with a 30% decoy confirm rate
/// is a lie — a renderer that shows the headline alone launders both
/// (SPEC §3.7).
#[must_use]
pub(crate) fn fidelity(score: &FidelityScore, by_facet: bool) -> String {
    todo!("render the score with sample size, CI, calibration and integrity signals")
}

/// Renders a footage as a human-readable recap.
///
/// Amendments to this day from later days are shown inline, so the reader sees
/// the corrected version while the chain still commits to what was originally
/// recorded (SPEC Q16).
#[must_use]
pub(crate) fn recap(footage: &Footage, amendments: &[Amendment]) -> String {
    todo!("render highlights, people, mood, threads and inline amendments")
}

/// Renders a persona diff.
///
/// Must be readable by someone who is not a developer. This is the review step
/// that catches a poisoned stance before it starts answering quests, and a
/// review nobody can perform is not a control (THREAT_MODEL §T7).
#[must_use]
pub(crate) fn persona_diff(diff: &PersonaDiff) -> String {
    todo!("render each change with its cause, grouped by facet")
}

/// Renders a verification report.
///
/// Skipped checks render differently from passed ones, and the header-source
/// trust level is stated. A verifier that overstates its own assurance is worse
/// than one that declines to run.
#[must_use]
pub(crate) fn verification(report: &VerificationReport) -> String {
    todo!("render each check with its status, and name the header source trust")
}

/// Warns, in plain language, that a seed leak is unrecoverable.
///
/// Shown at `gst init`, at the moment the seed exists — not in a footnote
/// someone reads afterwards.
#[must_use]
pub(crate) fn seed_warning() -> &'static str {
    todo!("return the plain-language seed warning")
}
