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
//! Four adapters are implemented: `markdown`, `journal`, `structlog`, and
//! `nostr`. The first three are the offline default set. `nostr` is off in a
//! default build and, unlike the others, cannot be constructed by
//! [`AdapterRegistry::with_builtins`] — it needs a relay client, and choosing
//! one is the composition root's job. `rss` and `archive` remain unimplemented.

#![forbid(unsafe_code)]
// CLAUDE.md §5 denies unwrap/expect/panic in library code, and names tests as
// the exception: a failed assertion should panic loudly with a message, and
// threading `Result` through test bodies buries what is actually being asserted.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]
pub mod adapter;
pub mod error;
#[cfg(feature = "journal")]
pub mod journal;
#[cfg(feature = "markdown")]
pub mod markdown;
#[cfg(feature = "nostr")]
pub mod nostr;
pub mod registry;
#[cfg(feature = "structlog")]
pub mod structlog;

pub use adapter::{IngestAdapter, IngestBatch};
pub use error::{Error, Result};
pub use registry::AdapterRegistry;
