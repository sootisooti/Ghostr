//! NIP-19: bech32 entity encoding.
//!
//! The human-facing form of nostr identifiers. `npub` and `note` are safe to
//! display anywhere; `nsec` is a secret key in a friendly costume and Ghostr
//! never renders one to a terminal, a log, or a QR code without an explicit,
//! separately confirmed user action.

use ghostr_core::identity::{Npub, PublicKey};

/// Encodes a public key as `npub1...`.
#[must_use]
pub fn encode_npub(pubkey: &PublicKey) -> Npub {
    todo!("bech32-encode the 32 key bytes with the `npub` HRP")
}

/// Decodes an `npub1...` string.
///
/// # Errors
///
/// Returns [`Error::InvalidBech32`](crate::Error::InvalidBech32) if the checksum
/// fails or the prefix is not `npub`, and
/// [`Error::InvalidPublicKey`](crate::Error::InvalidPublicKey) if the payload is
/// not a valid curve point.
pub fn decode_npub(npub: &Npub) -> crate::Result<PublicKey> {
    todo!("bech32-decode, check the HRP, validate the point")
}

/// A NIP-19 `nprofile`: a pubkey plus relay hints.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Nprofile {
    /// Whose profile.
    pub pubkey: PublicKey,
    /// Where to find them.
    pub relays: Vec<String>,
}

impl Nprofile {
    /// Encodes as `nprofile1...`.
    #[must_use]
    pub fn encode(&self) -> String {
        todo!("TLV-encode pubkey and relay hints, then bech32")
    }

    /// Decodes an `nprofile1...` string.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidBech32`](crate::Error::InvalidBech32) if the
    /// string is malformed or the TLV stream is truncated.
    pub fn decode(s: &str) -> crate::Result<Self> {
        todo!("bech32-decode and parse the TLV stream")
    }
}

/// A NIP-19 `naddr`: a coordinate for an addressable event.
///
/// This is how a Ghostr manifest or fidelity attestation is shared as one
/// string — the reference form for kinds 31780 and 31786 (SPEC §9).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Naddr {
    /// The `d` tag.
    pub identifier: String,
    /// The author.
    pub pubkey: PublicKey,
    /// The event kind.
    pub kind: u16,
    /// Relay hints.
    pub relays: Vec<String>,
}

impl Naddr {
    /// Encodes as `naddr1...`.
    #[must_use]
    pub fn encode(&self) -> String {
        todo!("TLV-encode identifier, pubkey, kind and relays, then bech32")
    }

    /// Decodes an `naddr1...` string.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidBech32`](crate::Error::InvalidBech32) if the
    /// string is malformed or a required TLV field is missing.
    pub fn decode(s: &str) -> crate::Result<Self> {
        todo!("bech32-decode and parse the TLV stream")
    }
}
