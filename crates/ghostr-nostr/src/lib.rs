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
//!
//! The mirror is not decoration. Kinds 31780–31789 are **unclaimed** (SPEC Q3),
//! so a reader that cannot resolve them must still be able to read a vault's
//! history; [`codec::mirror_as_nip78`] builds the kind-30078 copy and
//! [`codec::decode_mirrored`] reads either form. What never relaxes is the `d`
//! tag: kind 30078 is shared application data anyone may publish, so
//! `ghostr/v1/footage/7` is the only thing that says an event is a footage —
//! and it says so whatever number it was filed under, which is the property
//! that makes an unclaimed block survivable.
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
