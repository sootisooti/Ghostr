//! The daily compile pipeline (SPEC §6).
//!
//! Six stages. Stages 1–2 and 5–6 are deterministic and testable without a
//! model; only 3–4 touch an LLM.
//!
//! ```text
//! 1. Window  -> 2. Cluster -> 3. Extract -> 4. Compose -> 5. Seal -> 6. Anchor
//! ```
//!
//! # Two properties worth stating up front
//!
//! **Sealing is a point of no return.** Stage 5 makes the footage immutable and
//! advances the chain. It must be a single transaction: there is no valid state
//! between "not sealed" and "sealed", and a half-written link is
//! indistinguishable from a tampered one (SPEC I2, I3).
//!
//! **Anchoring comes after sealing, and may fail.** An anchoring outage delays a
//! proof; it never blocks a day from closing. A day that could not close because
//! a calendar was down would be a gap in the chain, which is a far worse
//! outcome than a proof arriving late.
//!
//! # Late arrivals never rewrite the past
//!
//! A nostr note from three days ago, pulled in today, does not retroactively
//! enter a sealed window. It lands in today's footage as an
//! [`Amendment`](ghostr_core::footage::Amendment) pointing back.
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

pub mod compose;
pub mod cutoff;
pub mod error;
pub mod extract;
pub mod pipeline;
pub mod summarize;

pub use error::{Error, Result};
pub use pipeline::{DraftFootage, MemoriaPipeline};
pub use summarize::{NaiveSummarizer, Summarizer};
