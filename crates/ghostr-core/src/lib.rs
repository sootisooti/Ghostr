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
//! Scaffold. Types and signatures are defined; bodies are [`todo!`].

#![forbid(unsafe_code)]
// SCAFFOLD: every function body in this crate is `todo!()`. These two allows
// exist only for the scaffold phase and are removed per-crate as bodies land.
// `unused_variables` fires because a diverging body never reads its arguments,
// and parameters are left named rather than `_`-prefixed so the signatures stay
// readable. `clippy::todo` is denied workspace-wide by CLAUDE.md §5; this is the
// documented exception. `cargo xtask scaffold-status` counts these markers so
// they cannot be quietly forgotten.
#![allow(unused_variables, clippy::todo)]

pub mod canonical;
pub mod error;
pub mod fidelity;
pub mod footage;
pub mod hash;
pub mod ids;
pub mod identity;
pub mod memory;
pub mod merkle;
pub mod persona;
pub mod quest;
pub mod sensitivity;
pub mod source;
pub mod time;

pub use error::{Error, Result};
