//! Building, diffing, and querying the persona model.
//!
//! The model is symbolic rather than a set of weights, and every design decision
//! here follows from that: claims carry evidence, versions diff, and a poisoned
//! belief can be traced to the note that introduced it and removed (SPEC §3.6).
//!
//! # Distillation is batched, not immediate
//!
//! A single correction never overturns a stance backed by fifty memories. Deltas
//! accumulate and apply at the next distillation, lowering `strength` and adding
//! to `contradicted_by` until the weight genuinely shifts — so a version bump
//! reflects a body of evidence rather than one bad morning (SPEC §4.5).
//!
//! # Contradictions are kept
//!
//! [`Stance::contradicted_by`](ghostr_core::persona::Stance::contradicted_by) is
//! never auto-resolved. People are inconsistent, and a model that smooths that
//! out is modelling a simpler person than the one it is cloning.
//!
//! # What is computed and what needs a model
//!
//! Voice, relationships, and routines are measurements — arithmetic over the
//! corpus, exact and available with no runtime installed. Opinions, boundaries,
//! and lore are not countable and come from a model; without one they are empty
//! rather than guessed, because a guessed stance is a confident claim with no
//! evidence behind it.
//!
//! # Status
//!
//! Implemented: deterministic distillation, content-hash versioning, the diff,
//! and retrieval. The model-backed facets arrive with the quest loop.

#![forbid(unsafe_code)]
// CLAUDE.md §5 denies unwrap/expect/panic in library code, and names tests as
// the exception: a failed assertion should panic loudly with a message, and
// threading `Result` through test bodies buries what is actually being asserted.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]
pub mod builder;
pub mod diff;
pub mod distill;
pub mod error;
pub mod retrieval;
pub mod voice;

pub use builder::{CandidateVersion, DeterministicBuilder, DistillInput, PersonaBuilder, propose};
pub use error::{Error, Result};
pub use retrieval::{Candidate, PolicyRetriever, RetrievalQuery, Retriever};
