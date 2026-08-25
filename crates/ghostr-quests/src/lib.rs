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
//! Scaffold. Types and signatures are defined; bodies are [`todo!`].

#![forbid(unsafe_code)]
// CLAUDE.md §5 denies unwrap/expect/panic in library code, and names tests as
// the exception: a failed assertion should panic loudly with a message, and
// threading `Result` through test bodies buries what is actually being asserted.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]
// SCAFFOLD: every function body in this crate is `todo!()`. These allows exist
// only for the scaffold phase and are removed crate-by-crate as bodies land.
// `unused_variables` and `dead_code` fire because a diverging body never reads
// its arguments and never calls its helpers; parameters keep real names rather
// than `_` prefixes so the signatures stay readable. `clippy::todo` is denied
// workspace-wide by CLAUDE.md §5 and this is the documented exception.
// `cargo xtask scaffold-status` counts these markers so they cannot be quietly
// forgotten.
#![allow(unused_variables, dead_code, clippy::todo)]

pub mod error;
pub mod generate;
pub mod score;
pub mod verdict;

pub use error::{Error, Result};
pub use generate::{QuestContext, QuestGenerator};
pub use score::{ScoredQuest, Scorer};
pub use verdict::VerdictIntake;
