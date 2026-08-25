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
//! Implemented. Deterministic clock and RNG, a scripted model, a recording
//! egress log, a synthetic corpus generator that hands back its own ground
//! truth, and the adversarial fixtures.

#![forbid(unsafe_code)]
// CLAUDE.md §5 denies unwrap/expect/panic in library code, and names tests as
// the exception: a failed assertion should panic loudly with a message, and
// threading `Result` through test bodies buries what is actually being asserted.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]
pub mod adversarial;
pub mod corpus;
pub mod fakes;
pub mod time;

pub use adversarial::{InjectionKind, injected_memory, poisoned_corpus, secret_bearing_text};
pub use corpus::{CorpusGenerator, GroundTruth, SyntheticCorpus};
pub use fakes::{RecordingEgressLog, ScriptedModel, ScriptedResponse};
pub use time::{FixedClock, SeededRng};
