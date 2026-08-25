//! NIP-19: bech32 entity encoding.
//!
//! The human-facing form of nostr identifiers. `npub` and `note` are safe to
//! display anywhere; `nsec` is a secret key in a friendly costume and Ghostr
//! never renders one to a terminal, a log, or a QR code without an explicit,
//! separately confirmed user action.

use ghostr_core::identity::{Npub, PublicKey};

/// Encodes a public key as `npub1...`.
///
/// # Panics
///
/// Cannot panic in practice: the `npub` HRP is a compile-time constant known to
/// be valid bech32, and a 32-byte payload is far below the length limit.
#[must_use]
pub fn encode_npub(pubkey: &PublicKey) -> Npub {
    let hrp = bech32::Hrp::parse_unchecked("npub");
    Npub::from_encoded(
        bech32::encode::<bech32::Bech32>(hrp, pubkey.as_bytes()).unwrap_or_else(|_| String::new()),
    )
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
    let (hrp, data) = bech32::decode(npub.as_str()).map_err(|_| crate::Error::InvalidBech32)?;
    if hrp.as_str() != "npub" {
        return Err(crate::Error::InvalidBech32);
    }
    let bytes: [u8; 32] = data.try_into().map_err(|_| crate::Error::InvalidBech32)?;
    // Validate the point here rather than in ghostr-core, which does not own the
    // curve: an npub that is not on the curve can never verify a signature, so
    // accepting it would only defer the failure.
    secp256k1::XOnlyPublicKey::from_byte_array(bytes)
        .map_err(|_| crate::Error::InvalidPublicKey)?;
    Ok(PublicKey::from_bytes(bytes))
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

#[cfg(test)]
mod tests {
    use super::*;

    /// NIP-19 test vector, verbatim from the NIPs repository.
    const NIP19_HEX: &str = "3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d";
    const NIP19_NPUB: &str = "npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkwsyjh6w6";

    #[test]
    fn nip19_vector_round_trips() {
        let key = PublicKey::from_hex(NIP19_HEX).expect("hex");
        let npub = encode_npub(&key);
        assert_eq!(npub.as_str(), NIP19_NPUB);
        assert_eq!(decode_npub(&npub).expect("decode"), key);
    }

    #[test]
    fn a_corrupted_checksum_is_rejected() {
        // Flip one character in the data part: bech32's checksum must catch it.
        let mut chars: Vec<char> = NIP19_NPUB.chars().collect();
        let last = chars.len() - 1;
        chars[last] = if chars[last] == 'q' { 'p' } else { 'q' };
        let broken = Npub::from_encoded(chars.into_iter().collect());
        assert!(decode_npub(&broken).is_err());
    }

    #[test]
    fn the_wrong_hrp_is_rejected() {
        // An `nsec` decodes as valid bech32 but must never be read as a pubkey.
        let hrp = bech32::Hrp::parse_unchecked("nsec");
        let encoded = bech32::encode::<bech32::Bech32>(hrp, &[7u8; 32]).expect("encode");
        assert!(decode_npub(&Npub::from_encoded(encoded)).is_err());
    }
}
