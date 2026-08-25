//! The composition root: wiring, scheduling, and the local API.
//!
//! This is the only crate that knows which implementations are real. It reads
//! config, unlocks the keystore, builds the store, resolves the model, and hands
//! out handles. Nothing depends on it.
//!
//! # It holds no domain logic
//!
//! If a rule about persona, scoring, or footage is being written here, it
//! belongs in the crate that owns it. The engine decides *when* things run and
//! *which* implementations run; never *what* they mean.
//!
//! # This is where the clock and the entropy live
//!
//! `clippy.toml` bans `SystemTime::now` and friends everywhere. The real
//! implementations are constructed here, behind an explicit
//! `#[allow(clippy::disallowed_methods)]` with a comment — so every exception in
//! the workspace is greppable and lands in one file (ARCHITECTURE §4.7).
//!
//! # Sealing must survive a sleeping laptop
//!
//! The job queue is durable, resumable, and at-least-once. A machine that sleeps
//! through its cutoff seals on wake rather than skipping a day, because a gap in
//! the chain is indistinguishable from a deletion (SPEC I3).
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

pub mod config;
pub mod engine;
pub mod error;
pub mod ops;
pub mod runtime;

pub use engine::Engine;
pub use error::{Error, Result};

/// Types the CLI renders, re-exported so it need not depend on the layers below.
///
/// ARCHITECTURE §3 rule 5: nothing depends on the engine, and the CLI depends on
/// nothing else. Re-exporting here keeps that true without the CLI reaching past
/// its one dependency.
pub mod types {
    pub use ghostr_core::footage::{Footage, Highlight, MoodReading, PersonBeat, Thread};
    pub use ghostr_core::hash::Hash32;
    pub use ghostr_core::identity::Npub;
    pub use ghostr_store::sqlite::{AnchorRecord, AnchorRecordState};
}
