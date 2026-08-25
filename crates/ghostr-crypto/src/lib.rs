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
//! - [`event`] — the minimal unsigned nostr event that signing operates on.
//!
//! # Unsafe
//!
//! Unlike every other crate in the workspace this one does not
//! `forbid(unsafe_code)`, because locking key material out of swap needs it. It
//! is still denied workspace-wide, so each site must opt in explicitly and carry
//! a safety comment.
//!
//! # Status
//!
//! Scaffold. Types and signatures are defined; bodies are [`todo!`].

// SCAFFOLD: every function body in this crate is `todo!()`. These allows exist
// only for the scaffold phase and are removed crate-by-crate as bodies land.
// `unused_variables` and `dead_code` fire because a diverging body never reads
// its arguments and never calls its helpers; parameters keep real names rather
// than `_` prefixes so the signatures stay readable. `clippy::todo` is denied
// workspace-wide by CLAUDE.md §5 and this is the documented exception.
// `cargo xtask scaffold-status` counts these markers so they cannot be quietly
// forgotten.
#![allow(unused_variables, dead_code, clippy::todo)]

pub mod error;
pub mod event;
pub mod kdf;
pub mod nip06;
pub mod nip19;
pub mod nip44;
pub mod secret;
pub mod signer;

pub use error::{Error, Result};
pub use signer::{Keystore, Signer};
