//! Key derivation, signing, and encryption for Ghostr.
//!
//! This crate is the boundary around secret key material. Everything outside it
//! holds a [`KeyRef`](ghostr_core::identity::KeyRef) and asks [`Signer`] to act;
//! nothing outside it can turn a reference into bytes (ARCHITECTURE §3 rule 4).
//! That indirection is what lets a NIP-46 remote signer or a hardware device
//! substitute for the local keystore without a single call site changing.
//!
//! # What lives here
//!
//! - [`Signer`] and [`Keystore`] — the two seams.
//! - [`nip06`] — BIP-39 seed, BIP-32 derivation at `m/44'/1237'/<account>'/0/0`.
//! - [`nip19`] — bech32 `npub` / `nsec` / `nprofile` encoding.
//! - [`nip44`] — v2 payload encryption, including self-encryption for app data.
//! - [`kdf`] — Argon2id passphrase stretching and the KEK/DEK hierarchy.
//! - [`keystore`] — the on-disk keystore file and its local implementation.
//! - [`event`] — the minimal unsigned nostr event that signing operates on.
//!
//! # Unsafe
//!
//! Unlike every other crate in the workspace this one does not
//! `forbid(unsafe_code)`, because locking key material out of swap needs it. It
//! is still denied workspace-wide, so each site must opt in explicitly and carry
//! a safety comment. There is exactly one such pair, in
//! [`secret::SecretPage`].
//!
//! # Status
//!
//! Implemented. Every NIP this crate names is checked against that NIP's own
//! vectors: NIP-06 against the NIP's derivation vector, NIP-19 against its
//! `npub` and `nprofile` examples, and NIP-44 v2 against all 128 cases in the
//! reference suite vendored under `vectors/`.
//!
//! [`FileKeystore`] implements both seams: it is the [`Keystore`] that unwraps
//! the seed and the [`Signer`] that uses it, because the secret bytes never
//! leave it.
//!
//! What is deliberately absent: NIP-46 remote signing has a [`Signer`] shape but
//! no transport; `nevent` and `nrelay` are not encoded, because nothing in
//! Ghostr references a non-addressable event; and
//! [`Keystore::change_passphrase`] refuses rather than rewrapping, because its
//! signature cannot carry the salt a rewrap needs (SPEC §14 Q19).
// CLAUDE.md §5 denies unwrap/expect/panic in library code, and names tests as
// the exception: a failed assertion should panic loudly with a message, and
// threading `Result` through test bodies buries what is actually being asserted.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

pub mod error;
pub mod event;
pub mod kdf;
pub mod keystore;
pub mod nip06;
pub mod nip19;
pub mod nip44;
pub mod secret;
pub mod signer;

pub use error::{Error, Result};
pub use keystore::FileKeystore;
pub use signer::{Keystore, Signer};
