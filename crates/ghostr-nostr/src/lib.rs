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
//! The codec is implemented: [`kinds`] addresses events, [`codec`] encodes and
//! decodes Ghostr's kinds against a [`Signer`](ghostr_crypto::Signer), mirrors
//! them under NIP-78, and enforces ghost disclosure by construction (SPEC I10).
//! [`privacy`] jitters publish times.
//!
//! Two things are deliberately absent. [`RelayClient`] is a trait with no
//! transport yet — the websocket half of M3. And
//! [`privacy::gift_wrap`] is `todo!()`: NIP-59 needs a throwaway signing key,
//! which cannot live in this crate (ARCHITECTURE §3 rule 4), so it waits on
//! SPEC §14 Q20 rather than on someone reaching for the shortcut.

#![forbid(unsafe_code)]
// CLAUDE.md §5 denies unwrap/expect/panic in library code, and names tests as
// the exception: a failed assertion should panic loudly with a message, and
// threading `Result` through test bodies buries what is actually being asserted.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]
// SCAFFOLD: one function is still `todo!()` — `privacy::gift_wrap`, blocked on
// SPEC §14 Q20. The allows are narrowed to what that single body needs:
// `unused_variables` because a diverging body never reads its arguments, and
// its parameters keep real names rather than `_` prefixes so the signature stays
// readable, and `clippy::todo`, which CLAUDE.md §5 denies workspace-wide and
// names this as the documented exception. `dead_code` is gone — nothing in this
// crate is unreachable any more.
//
// `cargo xtask scaffold-status` counts these markers, so the block cannot be
// quietly forgotten. Delete it when Q20 is answered.
#![allow(unused_variables, clippy::todo)]

pub mod client;
pub mod codec;
pub mod error;
pub mod kinds;
pub mod nip46;
pub mod payload;
pub mod privacy;

pub use client::{RelayClient, Subscription};
pub use error::{Error, Result};
pub use kinds::Kind;
