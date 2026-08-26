//! Quest generation, verdict intake, and fidelity scoring.
//!
//! This crate holds the product's central claim, which makes it the part most
//! worth attacking. Four controls keep the number honest (SPEC §4.4):
//!
//! | Control | What it catches |
//! | --- | --- |
//! | Holdout | The ghost being graded on its own training data |
//! | Decoys | A user rubber-stamping everything |
//! | Latency floor | Verdicts returned faster than a plausible read |
//! | Anchoring | Backdating a good streak |
//!
//! # The scorer is pure on purpose
//!
//! [`Scorer`] has no store, no model, and no clock. The fidelity number is the
//! thing a third party is asked to believe, so it must be reimplementable from
//! the spec in an afternoon and checkable against this one
//! (ARCHITECTURE §4.6).
//!
//! # What none of this fixes
//!
//! A patient, careful liar who reads each quest and confirms only the plausible
//! ones is not detected. What the system guarantees is that the *record* cannot
//! be changed afterwards — which is what makes a third party's trust in a
//! published score rational, given they also trust the client binary
//! (THREAT_MODEL §T9).
//!
//! # Status
//!
//! Implemented: fidelity scoring, quest generation with answer commitments, and
//! verdict intake. The three quest kinds that need a model to write their
//! prompt arrive with the model path.

#![forbid(unsafe_code)]
// CLAUDE.md §5 denies unwrap/expect/panic in library code, and names tests as
// the exception: a failed assertion should panic loudly with a message, and
// threading `Result` through test bodies buries what is actually being asserted.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]
pub mod error;
pub mod generate;
pub mod score;
pub mod verdict;

pub use error::{Error, Result};
pub use generate::{
    DeterministicGenerator, QuestContext, QuestGenerator, commit_answer, verify_commitment,
};
pub use score::{ScoredQuest, Scorer, StandardScorer};
pub use verdict::{CorrectionSlot, StandardIntake, VerdictIntake, VerdictOutcome};
