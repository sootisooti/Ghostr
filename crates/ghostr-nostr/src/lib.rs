//! Relay transport and the event codec for Ghostr's own kinds.
//!
//! # Relays are assumed hostile
//!
//! Nothing changes if a relay operator is malicious, because nothing readable is
//! ever published (SPEC I9). Private kinds carry NIP-44 self-encrypted content;
//! public kinds carry hashes and attestations that are meant to be read.
//!
//! What a relay *does* see is metadata NIP-44 does not cover: author pubkey,
//! event kind, `d` tag, `created_at`, and ciphertext length. A daily cadence of
//! same-kind events from one pubkey says "this person is alive, journaling, and
//! stopped on the 14th". [`privacy`] holds the mitigations — padding, jitter,
//! and gift wrap — and is honest that they blunt the signal rather than remove
//! it (THREAT_MODEL §T2).
//!
//! # Publishing is permanent
//!
//! Relays are append-only in practice. A key compromised in 2029 decrypts
//! ciphertext a relay stored in 2026. Every publish path is therefore off by
//! default and requires an explicit opt-in.
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

pub mod client;
pub mod codec;
pub mod error;
pub mod kinds;
pub mod payload;
pub mod privacy;

pub use client::{RelayClient, Subscription};
pub use error::{Error, Result};
pub use kinds::Kind;
