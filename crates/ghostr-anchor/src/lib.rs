//! The commitment chain, and its anchor into Bitcoin.
//!
//! Two halves, deliberately separated (ARCHITECTURE §4.5):
//!
//! - [`chain`] is **pure, synchronous, and I/O-free**. It is the part where a
//!   bug is unrecoverable — a wrong preimage silently forks every user's
//!   history and no migration can repair it, because the old hashes are already
//!   in Bitcoin. Being pure means it is testable with fixed vectors and property
//!   tests, and never needs a mock server.
//! - [`ots`] and [`verify`] talk to calendars and block headers. Failure there
//!   is recoverable: an unanchored seal is still a valid chain link, just
//!   without an external time attestation yet.
//!
//! # What anchoring proves
//!
//! That a hash existed no later than a block time, and that the ordering of the
//! chain is what it claims. **Not** that the content is true, and not that a
//! memory was not composed earlier and backdated within the app before sealing.
//! Anchoring establishes existence and ordering, never honesty
//! (SPEC §7.4, THREAT_MODEL §T9).
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

pub mod chain;
pub mod error;
pub mod ots;
pub mod verify;

pub use chain::CommitmentChain;
pub use error::{Error, Result};
pub use ots::{AnchorState, Anchorer, PendingProof, Proof};
pub use verify::{BlockHeaderSource, HeaderTrust};
