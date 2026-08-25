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
//! Implemented. Stages 1–2 and 5–6 are deterministic; stages 3–4 use a model
//! when the `llm` feature is on and fall back to the deterministic extractor
//! when it is off or the runtime is unreachable.

#![forbid(unsafe_code)]
// CLAUDE.md §5 denies unwrap/expect/panic in library code, and names tests as
// the exception: a failed assertion should panic loudly with a message, and
// threading `Result` through test bodies buries what is actually being asserted.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]
pub mod compose;
pub mod cutoff;
pub mod error;
pub mod extract;
#[cfg(feature = "llm")]
pub mod llm;
pub mod pipeline;
pub mod summarize;

pub use error::{Error, Result};
pub use pipeline::{DraftFootage, MemoriaPipeline, drop_unevidenced, validate_draft};
pub use summarize::{NaiveSummarizer, Summarizer};
