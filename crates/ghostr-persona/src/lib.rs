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
//! # Status
//!
//! Scaffold. Types and signatures are defined; bodies are [`todo!`].

#![forbid(unsafe_code)]
// SCAFFOLD: every function body in this crate is `todo!()`. These allows exist
// only for the scaffold phase and are removed crate-by-crate as bodies land.
// `unused_variables` and `dead_code` fire because a diverging body never reads
// its arguments and never calls its helpers; parameters keep real names rather
// than `_` prefixes so the signatures stay readable. `clippy::todo` is denied
// workspace-wide by CLAUDE.md §5 and this is the documented exception.
// `cargo xtask scaffold-status` counts these markers so they cannot be quietly
// forgotten.
#![allow(unused_variables, dead_code, clippy::todo)]

pub mod builder;
pub mod error;
pub mod retrieval;

pub use builder::{DistillInput, PersonaBuilder};
pub use error::{Error, Result};
pub use retrieval::{RetrievalQuery, Retriever};
