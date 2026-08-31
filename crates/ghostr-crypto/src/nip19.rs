//! NIP-19: bech32 entity encoding.
//!
//! The human-facing form of nostr identifiers. `npub` and `note` are safe to
//! display anywhere; `nsec` is a secret key in a friendly costume and Ghostr
//! never renders one to a terminal, a log, or a QR code without an explicit,
//! separately confirmed user action.

use bech32::primitives::decode::CheckedHrpstring;
use ghostr_core::identity::{Npub, PublicKey};

use crate::secret::SecretBytes;

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

/// Decodes an `nsec1...` into raw secret key bytes.
///
/// # This returns a secret, and says so in its type
///
/// Everything else in this module deals in public values. This one does not: an
/// `nsec` *is* the private key, in a friendly costume. The return type is
/// [`SecretBytes`] so it zeroizes on drop and cannot
/// be printed, and the input is [`SecretString`](crate::secret::SecretString) so
/// the encoded form gets the same treatment — a bare `&str` would leave the key
/// sitting in whatever buffer the caller read it into.
///
/// The curve point is **not** validated here. That happens where the key is
/// adopted, so an unusable key is refused at import with the user still looking
/// at what they pasted.
///
/// # Errors
///
/// Returns [`Error::InvalidBech32`](crate::Error::InvalidBech32) if the checksum
/// fails, the prefix is not `nsec`, or the payload is not 32 bytes.
pub fn decode_nsec(nsec: &crate::secret::SecretString) -> crate::Result<SecretBytes<32>> {
    let (hrp, data) = bech32::decode(nsec.expose()).map_err(|_| crate::Error::InvalidBech32)?;
    if hrp.as_str() != "nsec" {
        return Err(crate::Error::InvalidBech32);
    }
    let bytes: [u8; 32] = data.try_into().map_err(|_| crate::Error::InvalidBech32)?;
    Ok(SecretBytes::new(bytes))
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
    ///
    /// # Errors
    ///
    /// Returns [`Error::Bech32TooLong`](crate::Error::Bech32TooLong) if a relay
    /// hint exceeds 255 bytes or the hints together push the string past
    /// NIP-19's 5000-character ceiling.
    pub fn encode(&self) -> crate::Result<String> {
        let mut tlv = Vec::new();
        push_tlv(&mut tlv, TLV_SPECIAL, self.pubkey.as_bytes())?;
        for relay in &self.relays {
            push_tlv(&mut tlv, TLV_RELAY, relay.as_bytes())?;
        }
        encode_tlv_entity("nprofile", &tlv)
    }

    /// Decodes an `nprofile1...` string.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidBech32`](crate::Error::InvalidBech32) if the
    /// string is malformed, the TLV stream is truncated, or the `special`
    /// record is missing, and
    /// [`Error::InvalidPublicKey`](crate::Error::InvalidPublicKey) if the pubkey
    /// it carries is not a curve point.
    pub fn decode(s: &str) -> crate::Result<Self> {
        let bytes = decode_tlv_entity(s, "nprofile")?;
        let records = parse_tlv(&bytes)?;

        let mut pubkey = None;
        let mut relays = Vec::new();
        for (tag, value) in records {
            match tag {
                // First record wins. A second `special` is not a correction —
                // it is an ambiguity, and picking either one lets two decoders
                // disagree about who a string names.
                TLV_SPECIAL if pubkey.is_none() => pubkey = Some(tlv_pubkey(value)?),
                TLV_RELAY => relays.push(tlv_relay(value)?),
                // NIP-19: unrecognized TLV types are ignored, not rejected, so a
                // tag added to the NIP later does not break this decoder.
                _ => {}
            }
        }

        Ok(Self {
            pubkey: pubkey.ok_or(crate::Error::InvalidBech32)?,
            relays,
        })
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
    ///
    /// # Errors
    ///
    /// Returns [`Error::Bech32TooLong`](crate::Error::Bech32TooLong) if the
    /// identifier or a relay hint exceeds 255 bytes, or the whole string would
    /// pass NIP-19's 5000-character ceiling.
    pub fn encode(&self) -> crate::Result<String> {
        let mut tlv = Vec::new();
        push_tlv(&mut tlv, TLV_SPECIAL, self.identifier.as_bytes())?;
        for relay in &self.relays {
            push_tlv(&mut tlv, TLV_RELAY, relay.as_bytes())?;
        }
        push_tlv(&mut tlv, TLV_AUTHOR, self.pubkey.as_bytes())?;
        push_tlv(&mut tlv, TLV_KIND, &u32::from(self.kind).to_be_bytes())?;
        encode_tlv_entity("naddr", &tlv)
    }

    /// Decodes an `naddr1...` string.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidBech32`](crate::Error::InvalidBech32) if the
    /// string is malformed or a required TLV field is missing, and
    /// [`Error::InvalidPublicKey`](crate::Error::InvalidPublicKey) if the author
    /// it carries is not a curve point.
    pub fn decode(s: &str) -> crate::Result<Self> {
        let bytes = decode_tlv_entity(s, "naddr")?;
        let records = parse_tlv(&bytes)?;

        let mut identifier = None;
        let mut pubkey = None;
        let mut kind = None;
        let mut relays = Vec::new();
        for (tag, value) in records {
            match tag {
                // First record wins, for each of the three singular fields — see
                // `Nprofile::decode`.
                TLV_SPECIAL if identifier.is_none() => {
                    identifier = Some(tlv_string(value)?);
                }
                TLV_RELAY => relays.push(tlv_relay(value)?),
                TLV_AUTHOR if pubkey.is_none() => pubkey = Some(tlv_pubkey(value)?),
                TLV_KIND if kind.is_none() => kind = Some(tlv_kind(value)?),
                _ => {}
            }
        }

        Ok(Self {
            // An empty `d` tag is legal — NIP-19 names it as the form for a
            // normal replaceable event — so absence, not emptiness, is the error.
            identifier: identifier.ok_or(crate::Error::InvalidBech32)?,
            pubkey: pubkey.ok_or(crate::Error::InvalidBech32)?,
            kind: kind.ok_or(crate::Error::InvalidBech32)?,
            relays,
        })
    }
}

// ---------------------------------------------------------------------------
// TLV
// ---------------------------------------------------------------------------

/// `special`: the pubkey for `nprofile`, the `d` tag for `naddr`.
const TLV_SPECIAL: u8 = 0;
/// `relay`: a hint at where to look. May repeat.
const TLV_RELAY: u8 = 1;
/// `author`: the 32-byte pubkey of an addressable event.
const TLV_AUTHOR: u8 = 2;
/// `kind`: a 32-bit big-endian event kind.
const TLV_KIND: u8 = 3;

/// bech32 with nostr's length ceiling rather than the bech32 crate's default.
///
/// [`bech32::Bech32`] stops at 1023 characters; NIP-19 asks for 5000, and a
/// coordinate carrying a long identifier and a handful of relay hints passes
/// 1023 without trying. Every other constant is delegated to the crate's own
/// impl rather than copied: a transcribed generator polynomial is a place to be
/// silently, undetectably wrong.
enum NostrBech32 {}

impl bech32::Checksum for NostrBech32 {
    type MidstateRepr = <bech32::Bech32 as bech32::Checksum>::MidstateRepr;
    const CHECKSUM_LENGTH: usize = <bech32::Bech32 as bech32::Checksum>::CHECKSUM_LENGTH;
    const CODE_LENGTH: usize = 5000;
    const GENERATOR_SH: [Self::MidstateRepr; 5] =
        <bech32::Bech32 as bech32::Checksum>::GENERATOR_SH;
    const TARGET_RESIDUE: Self::MidstateRepr = <bech32::Bech32 as bech32::Checksum>::TARGET_RESIDUE;
}

/// Appends one TLV record.
///
/// `L` is a single byte, so a value over 255 bytes has no representation at
/// all. Refused rather than truncated: a shortened relay URL still decodes
/// cleanly, just into a different relay.
fn push_tlv(out: &mut Vec<u8>, tag: u8, value: &[u8]) -> crate::Result<()> {
    let len = u8::try_from(value.len()).map_err(|_| crate::Error::Bech32TooLong)?;
    out.push(tag);
    out.push(len);
    out.extend_from_slice(value);
    Ok(())
}

/// bech32-encodes a finished TLV stream under `hrp`.
fn encode_tlv_entity(hrp: &str, tlv: &[u8]) -> crate::Result<String> {
    let hrp = bech32::Hrp::parse(hrp).map_err(|_| crate::Error::InvalidBech32)?;
    bech32::encode::<NostrBech32>(hrp, tlv).map_err(|_| crate::Error::Bech32TooLong)
}

/// bech32-decodes `s`, checking the prefix, and returns the TLV stream.
///
/// Uses [`CheckedHrpstring`] rather than [`bech32::decode`] for two reasons: the
/// top-level helper caps the string at 1023 characters, and it accepts bech32
/// *or* bech32m. NIP-19 entities are bech32 — accepting bech32m as well would
/// let two distinct strings name the same profile.
fn decode_tlv_entity(s: &str, expected_hrp: &str) -> crate::Result<Vec<u8>> {
    let parsed =
        CheckedHrpstring::new::<NostrBech32>(s).map_err(|_| crate::Error::InvalidBech32)?;
    if parsed.hrp().as_str() != expected_hrp {
        return Err(crate::Error::InvalidBech32);
    }
    Ok(parsed.byte_iter().collect())
}

/// Splits a TLV stream into `(tag, value)` records.
///
/// A truncated record is an error. An *unknown* tag is not: NIP-19 requires
/// unrecognized types be ignored, so parsing must survive a record it cannot
/// interpret — which it can, because the length prefix tells it how far to skip.
fn parse_tlv(mut bytes: &[u8]) -> crate::Result<Vec<(u8, &[u8])>> {
    let mut records = Vec::new();
    while let Some((&tag, rest)) = bytes.split_first() {
        let (&len, rest) = rest.split_first().ok_or(crate::Error::InvalidBech32)?;
        let len = usize::from(len);
        if rest.len() < len {
            return Err(crate::Error::InvalidBech32);
        }
        let (value, tail) = rest.split_at(len);
        records.push((tag, value));
        bytes = tail;
    }
    Ok(records)
}

/// Reads a 32-byte TLV value as a public key, validating the curve point.
///
/// Same reasoning as [`decode_npub`]: a key that is not on the curve can never
/// verify a signature, so accepting it only defers the failure to somewhere with
/// less context.
fn tlv_pubkey(value: &[u8]) -> crate::Result<PublicKey> {
    let bytes: [u8; 32] = value.try_into().map_err(|_| crate::Error::InvalidBech32)?;
    secp256k1::XOnlyPublicKey::from_byte_array(bytes)
        .map_err(|_| crate::Error::InvalidPublicKey)?;
    Ok(PublicKey::from_bytes(bytes))
}

/// Reads a TLV value as UTF-8.
fn tlv_string(value: &[u8]) -> crate::Result<String> {
    String::from_utf8(value.to_vec()).map_err(|_| crate::Error::InvalidBech32)
}

/// Reads a relay hint.
///
/// NIP-19 says relay hints are ASCII. Enforced rather than assumed: a hint is a
/// URL Ghostr may later connect to, and a non-ASCII byte there is either a
/// corrupt string or a homograph aimed at the person reading it.
fn tlv_relay(value: &[u8]) -> crate::Result<String> {
    if !value.is_ascii() {
        return Err(crate::Error::InvalidBech32);
    }
    tlv_string(value)
}

/// Reads a 32-bit big-endian TLV value as an event kind.
///
/// Narrowed to `u16` to match [`UnsignedEvent::kind`](crate::event::UnsignedEvent::kind),
/// which is what NIP-01 events actually carry. A kind above 65535 is not a
/// Ghostr kind and not a nostr kind, so it is refused rather than wrapped.
fn tlv_kind(value: &[u8]) -> crate::Result<u16> {
    let bytes: [u8; 4] = value.try_into().map_err(|_| crate::Error::InvalidBech32)?;
    u16::try_from(u32::from_be_bytes(bytes)).map_err(|_| crate::Error::InvalidBech32)
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

    /// NIP-19 test vector, verbatim from the NIPs repository (retrieved
    /// 2026-08-27). The only `nprofile` the NIP publishes, and the only thing
    /// that proves this encoder agrees with every other nostr implementation
    /// rather than merely with itself.
    const NIP19_NPROFILE: &str = "nprofile1qqsrhuxx8l9ex335q7he0f09aej04zpazpl0ne2cgukyawd24mayt8gpp4mhxue69uhhytnc9e3k7mgpz4mhxue69uhkg6nzv9ejuumpv34kytnrdaksjlyr9p";
    const NIP19_NPROFILE_PUBKEY: &str =
        "3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d";
    const NIP19_NPROFILE_RELAYS: [&str; 2] = ["wss://r.x.com", "wss://djbas.sadkb.com"];

    #[test]
    fn nip19_nprofile_vector_decodes() {
        let profile = Nprofile::decode(NIP19_NPROFILE).expect("decode");
        assert_eq!(
            profile.pubkey,
            PublicKey::from_hex(NIP19_NPROFILE_PUBKEY).expect("hex")
        );
        assert_eq!(profile.relays, NIP19_NPROFILE_RELAYS);
    }

    #[test]
    fn nip19_nprofile_vector_re_encodes() {
        // Byte-for-byte, not just semantically: TLV record order is a free
        // choice the NIP does not pin down, and picking a different one would
        // still round-trip here while producing a string no other client's
        // vector matches.
        let profile = Nprofile {
            pubkey: PublicKey::from_hex(NIP19_NPROFILE_PUBKEY).expect("hex"),
            relays: NIP19_NPROFILE_RELAYS
                .iter()
                .map(|s| (*s).to_owned())
                .collect(),
        };
        assert_eq!(profile.encode().expect("encode"), NIP19_NPROFILE);
    }

    #[test]
    fn an_entity_past_the_crates_default_ceiling_still_round_trips() {
        // The reason `NostrBech32` exists at all: `bech32::decode` refuses past
        // 1023 characters, and NIP-19 allows 5000.
        let profile = Nprofile {
            pubkey: PublicKey::from_hex(NIP19_HEX).expect("hex"),
            relays: (0..16)
                .map(|i| format!("wss://relay-{i:02}.example.invalid/ghostr/hint/padding"))
                .collect(),
        };
        let encoded = profile.encode().expect("encode");

        assert!(encoded.len() > 1023);
        assert!(bech32::decode(&encoded).is_err());
        assert_eq!(Nprofile::decode(&encoded).expect("decode"), profile);
    }

    #[test]
    fn the_same_bytes_under_bech32m_are_not_accepted() {
        // `bech32::decode` takes either checksum. NIP-19 entities are bech32, and
        // if both were accepted two different strings would name one profile —
        // enough for two clients to disagree about what a user shared.
        let pubkey = PublicKey::from_hex(NIP19_HEX).expect("hex");
        let mut tlv = Vec::new();
        push_tlv(&mut tlv, TLV_SPECIAL, pubkey.as_bytes()).expect("special");
        let hrp = bech32::Hrp::parse_unchecked("nprofile");
        let bech32m = bech32::encode::<bech32::Bech32m>(hrp, &tlv).expect("encode");

        assert!(bech32::decode(&bech32m).is_ok());
        assert!(Nprofile::decode(&bech32m).is_err());
    }

    #[test]
    fn the_nostr_code_is_internally_consistent() {
        // The crate asks every `Checksum` implementor to run this. It is what
        // catches a generator polynomial that was mistyped rather than delegated.
        <NostrBech32 as bech32::Checksum>::sanity_check();
        assert_eq!(
            <NostrBech32 as bech32::Checksum>::CHECKSUM_LENGTH,
            <bech32::Bech32 as bech32::Checksum>::CHECKSUM_LENGTH
        );
    }

    #[test]
    fn an_naddr_round_trips() {
        let naddr = Naddr {
            identifier: "2026-08-27".to_owned(),
            pubkey: PublicKey::from_hex(NIP19_HEX).expect("hex"),
            // SPEC §9: the Ghostr manifest kind.
            kind: 31780,
            relays: vec!["wss://relay.damus.io".to_owned()],
        };
        let encoded = naddr.encode().expect("encode");
        assert!(encoded.starts_with("naddr1"));
        assert_eq!(Naddr::decode(&encoded).expect("decode"), naddr);
    }

    #[test]
    fn an_naddr_with_an_empty_identifier_round_trips() {
        // NIP-19 names the empty `d` tag as the form for a normal replaceable
        // event, so "missing" and "empty" must not collapse into one case.
        let naddr = Naddr {
            identifier: String::new(),
            pubkey: PublicKey::from_hex(NIP19_HEX).expect("hex"),
            kind: 0,
            relays: Vec::new(),
        };
        let encoded = naddr.encode().expect("encode");
        assert_eq!(Naddr::decode(&encoded).expect("decode"), naddr);
    }

    #[test]
    fn the_naddr_tlv_stream_is_the_shape_nip19_describes() {
        // Reading the bytes rather than the round-trip: a decoder that agreed
        // with this encoder's private mistakes would pass every test above.
        let naddr = Naddr {
            identifier: "d".to_owned(),
            pubkey: PublicKey::from_hex(NIP19_HEX).expect("hex"),
            kind: 31780,
            relays: vec!["wss://r.x.com".to_owned()],
        };
        let encoded = naddr.encode().expect("encode");
        let tlv = decode_tlv_entity(&encoded, "naddr").expect("decode");

        let mut expected = vec![0u8, 1, b'd'];
        expected.extend_from_slice(&[1u8, 13]);
        expected.extend_from_slice(b"wss://r.x.com");
        expected.extend_from_slice(&[2u8, 32]);
        expected.extend_from_slice(naddr.pubkey.as_bytes());
        expected.extend_from_slice(&[3u8, 4, 0, 0, 0x7c, 0x24]);
        assert_eq!(tlv, expected);
        // 31780 spelled out, so a wrong endianness above cannot hide.
        assert_eq!(u32::from_be_bytes([0, 0, 0x7c, 0x24]), 31780);
    }

    #[test]
    fn an_unknown_tlv_type_is_ignored_rather_than_rejected() {
        // NIP-19: "TLVs that are not recognized or supported should be ignored".
        let pubkey = PublicKey::from_hex(NIP19_HEX).expect("hex");
        let mut tlv = Vec::new();
        push_tlv(&mut tlv, TLV_SPECIAL, pubkey.as_bytes()).expect("special");
        push_tlv(&mut tlv, 250, b"from a future NIP").expect("unknown");
        push_tlv(&mut tlv, TLV_RELAY, b"wss://r.x.com").expect("relay");
        let encoded = encode_tlv_entity("nprofile", &tlv).expect("encode");

        let profile = Nprofile::decode(&encoded).expect("decode");
        assert_eq!(profile.pubkey, pubkey);
        assert_eq!(profile.relays, ["wss://r.x.com"]);
    }

    #[test]
    fn a_truncated_tlv_stream_is_refused() {
        // The length byte claims more than the stream holds. Skipping the record
        // would silently accept a string an attacker cut short.
        assert!(parse_tlv(&[TLV_RELAY, 10, b'a']).is_err());
        // A tag with no length byte at all.
        assert!(parse_tlv(&[TLV_RELAY]).is_err());
    }

    #[test]
    fn an_nprofile_without_a_pubkey_is_refused() {
        let mut tlv = Vec::new();
        push_tlv(&mut tlv, TLV_RELAY, b"wss://r.x.com").expect("relay");
        let encoded = encode_tlv_entity("nprofile", &tlv).expect("encode");
        assert!(Nprofile::decode(&encoded).is_err());
    }

    #[test]
    fn an_nprofile_is_not_an_naddr() {
        // Same TLV grammar, different meaning. Decoding one as the other would
        // read a pubkey as a `d` tag.
        assert!(Naddr::decode(NIP19_NPROFILE).is_err());
    }

    #[test]
    fn an_over_long_relay_hint_is_refused_not_truncated() {
        let profile = Nprofile {
            pubkey: PublicKey::from_hex(NIP19_HEX).expect("hex"),
            relays: vec!["w".repeat(256)],
        };
        assert!(matches!(profile.encode(), Err(crate::Error::Bech32TooLong)));
    }

    #[test]
    fn a_kind_above_the_nostr_range_is_refused() {
        // 65536 fits the wire format's 32 bits but is not a nostr kind.
        let author = PublicKey::from_hex(NIP19_HEX).expect("hex");
        let mut tlv = Vec::new();
        push_tlv(&mut tlv, TLV_SPECIAL, b"d").expect("special");
        push_tlv(&mut tlv, TLV_AUTHOR, author.as_bytes()).expect("author");
        push_tlv(&mut tlv, TLV_KIND, &65_536u32.to_be_bytes()).expect("kind");
        let encoded = encode_tlv_entity("naddr", &tlv).expect("encode");
        assert!(Naddr::decode(&encoded).is_err());
    }

    #[test]
    fn a_non_ascii_relay_hint_is_refused() {
        let pubkey = PublicKey::from_hex(NIP19_HEX).expect("hex");
        let mut tlv = Vec::new();
        push_tlv(&mut tlv, TLV_SPECIAL, pubkey.as_bytes()).expect("special");
        push_tlv(&mut tlv, TLV_RELAY, "wss://релay.example".as_bytes()).expect("relay");
        let encoded = encode_tlv_entity("nprofile", &tlv).expect("encode");
        assert!(Nprofile::decode(&encoded).is_err());
    }

    #[test]
    fn the_wrong_hrp_is_rejected() {
        // An `nsec` decodes as valid bech32 but must never be read as a pubkey.
        let hrp = bech32::Hrp::parse_unchecked("nsec");
        let encoded = bech32::encode::<bech32::Bech32>(hrp, &[7u8; 32]).expect("encode");
        assert!(decode_npub(&Npub::from_encoded(encoded)).is_err());
    }
}
