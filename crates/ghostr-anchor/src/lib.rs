//! The commitment chain, and its anchor into Bitcoin.
//!
//! Two halves, deliberately separated (ARCHITECTURE §4.5):
//!
//! - [`chain`] is **pure, synchronous, and I/O-free**. Free functions rather
//!   than a trait: there is exactly one scheme at a time, its version is a
//!   constant, and a trait with a single implementation would be abstraction
//!   ahead of a second version that does not exist yet (CLAUDE.md §9). If a v2
//!   ever needs to coexist with v1, that is when the seam earns its keep. It is the part where a
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
//! Implemented. The commitment chain is pure; OpenTimestamps is the one
//! networked path, and it degrades to a recorded failure rather than blocking a
//! day from closing.

#![forbid(unsafe_code)]
// CLAUDE.md §5 denies unwrap/expect/panic in library code, and names tests as
// the exception: a failed assertion should panic loudly with a message, and
// threading `Result` through test bodies buries what is actually being asserted.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]
pub mod chain;
pub mod error;
pub mod ots;
pub mod verify;

pub use chain::{
    CHAIN_VERSION, ChainRecord, genesis, link, memory_leaf, meta_leaf, quest_leaf, root,
    verdict_leaf, verify_run,
};
pub use error::{Error, Result};
pub use ots::{AnchorState, CalendarConfig, OtsClient, Submission, default_calendars};
pub use verify::{CheckResult, HeaderTrust, VerificationReport};
