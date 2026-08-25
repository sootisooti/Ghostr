//! Test doubles, fixtures, and deterministic seams.
//!
//! The first thing a contributor should reach for. Everything here exists so a
//! test can run the real logic against fake edges: no database, no model, no
//! network, no clock.
//!
//! # No test touches the network
//!
//! A network call in a test is a CI failure (CLAUDE.md §6). Real relay and
//! OpenTimestamps interaction lives in an `#[ignore]`d suite run nightly.
//!
//! # Determinism is the point
//!
//! [`FixedClock`] and [`SeededRng`] make sealing, salting, cutoff windows, and
//! holdout selection reproducible. Without them the interesting bugs — the
//! cutoff at midnight, the timezone change mid-day, the empty window — only
//! appear in production, at midnight.
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

pub mod adversarial;
pub mod corpus;
pub mod fakes;
pub mod time;

pub use fakes::{RecordingEgressLog, ScriptedModel};
pub use time::{FixedClock, SeededRng};
