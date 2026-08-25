//! Ghostr domain types, canonical serialization, and commitment primitives.
//!
//! This crate is a leaf: it has no I/O, no async, and no dependency that opens a
//! file or a socket (ARCHITECTURE §3 rule 1). Everything here is a type, a pure
//! function, or a trait declaration, which is what makes the commitment scheme
//! property-testable and keeps hashing from drifting with storage changes.
//!
//! # Layout
//!
//! - [`ids`] — newtype identifiers. Never a bare `Uuid`.
//! - [`time`] — [`time::Timestamp`], and the [`time::Clock`] / [`time::Rng`]
//!   determinism seams.
//! - [`sensitivity`] — [`sensitivity::Sensitivity`], the enum the egress
//!   boundary reads.
//! - [`memory`], [`source`], [`footage`], [`quest`], [`persona`], [`fidelity`],
//!   [`identity`] — the seven domain models of SPEC §3.
//! - [`hash`], [`merkle`], [`canonical`] — the commitment primitives of SPEC §7.
//! - [`error`] — this crate's error type.
//!
//! # Status
//!
//! Implemented. Every public item in this crate has a body.

#![forbid(unsafe_code)]
// CLAUDE.md §5 denies unwrap/expect/panic in library code, and names tests as
// the exception: a failed assertion should panic loudly with a message, and
// threading `Result` through test bodies buries what is actually being asserted.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]
pub mod canonical;
pub mod error;
pub mod fidelity;
pub mod footage;
pub mod hash;
pub mod identity;
pub mod ids;
pub mod memory;
pub mod merkle;
pub mod persona;
pub mod quest;
pub mod sensitivity;
pub mod source;
pub mod time;

pub use error::{Error, Result};
