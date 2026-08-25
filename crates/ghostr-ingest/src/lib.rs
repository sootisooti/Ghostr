//! Source adapters: everything that turns outside data into
//! [`Memory`](ghostr_core::memory::Memory) values.
//!
//! # Adding a source
//!
//! Implement [`IngestAdapter`], register it, and add a fixture-driven test from
//! `ghostr-testkit`. Nothing else in the tree changes. That is the whole
//! contract, and keeping it that small is what makes this the natural first
//! contribution to the project.
//!
//! # This is the hostile-input boundary
//!
//! `nostr`, `rss`, and `archive` sources carry text written by other people, and
//! that text is fed to a language model. An adapter's
//! [`IngestAdapter::default_trust`] is a security control, not a quality
//! signal:
//! [`TrustLevel::ThirdParty`](ghostr_core::sensitivity::TrustLevel::ThirdParty)
//! content never becomes a voice exemplar and
//! never sources a claim about what the user believes
//! (THREAT_MODEL §T7).
//!
//! An adapter that returns
//! [`TrustLevel::FirstParty`](ghostr_core::sensitivity::TrustLevel::FirstParty)
//! for content the user did
//! not write is a vulnerability, not a bug.
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

pub mod adapter;
pub mod error;
pub mod markdown;
pub mod registry;

pub use adapter::{IngestAdapter, IngestBatch};
pub use error::{Error, Result};
pub use registry::AdapterRegistry;
