//! Parsing the `bunker://` URL a remote signer hands the user.
//!
//! This is the whole user-facing surface of remote signing: nsecBunker, nsec.app
//! and Amber all present a string, and the user pastes it. Everything else in
//! `nip46` follows from what this returns.
//!
//! ```text
//! bunker://<remote-signer-pubkey>?relay=<wss://…>&relay=<wss://…>&secret=<…>
//! ```
//!
//! # Parsed strictly, on purpose
//!
//! What comes out of here decides *who this vault will treat as its signer* and
//! *which relays it will talk to*. A lenient parser that guesses at a malformed
//! string is choosing those on the user's behalf from something they may have
//! mistyped, or been sent. So: the pubkey must be 32 hex bytes on the curve, at
//! least one relay must be present, and a relay must be `wss://` or `ws://` —
//! anything else is refused rather than repaired.

use ghostr_core::identity::PublicKey;
use ghostr_crypto::secret::SecretString;

/// A parsed `bunker://` URL.
pub struct BunkerUrl {
    /// The remote signer's own pubkey — *not* the user's.
    ///
    /// NIP-46 keeps these separate, and conflating them is the mistake the NIP
    /// warns about: the user's key is learned afterwards, by asking.
    pub signer_pubkey: PublicKey,
    /// Relays to reach the signer on. At least one.
    pub relays: Vec<String>,
    /// A one-time connection secret, if the signer issued one.
    pub secret: Option<SecretString>,
}

impl core::fmt::Debug for BunkerUrl {
    /// The secret is a credential and is never printed, not even redacted in a
    /// way that reveals its length.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("BunkerUrl")
            .field("signer", &self.signer_pubkey.short())
            .field("relays", &self.relays.len())
            .field("has_secret", &self.secret.is_some())
            .finish()
    }
}

impl BunkerUrl {
    /// Parses a `bunker://` URL.
    ///
    /// # Errors
    ///
    /// Returns [`Error::MalformedBunkerUrl`](crate::Error::MalformedBunkerUrl)
    /// if the scheme is not `bunker://`, the pubkey is not 32 hex bytes on the
    /// curve, no relay is given, or a relay is not a websocket URL.
    pub fn parse(url: &str) -> crate::Result<Self> {
        let bad = || crate::Error::MalformedBunkerUrl;

        let rest = url.trim().strip_prefix("bunker://").ok_or_else(bad)?;
        let (pubkey_hex, query) = match rest.split_once('?') {
            Some((key, query)) => (key, query),
            // No query means no relays, and a signer with no relays cannot be
            // reached — NIP-46 has no other transport.
            None => return Err(bad()),
        };

        let signer_pubkey = parse_pubkey(pubkey_hex)?;

        let mut relays = Vec::new();
        let mut secret = None;
        for pair in query.split('&') {
            let Some((name, value)) = pair.split_once('=') else {
                continue;
            };
            let value = percent_decode(value);
            match name {
                "relay" => {
                    if !value.starts_with("wss://") && !value.starts_with("ws://") {
                        return Err(bad());
                    }
                    relays.push(value);
                }
                "secret" => secret = Some(SecretString::new(value)),
                // Unknown parameters are ignored rather than refused: NIP-46
                // gains them over time, and a client that rejects a URL for
                // carrying one it has not heard of breaks on the signer's next
                // release.
                _ => {}
            }
        }

        if relays.is_empty() {
            return Err(bad());
        }
        Ok(Self {
            signer_pubkey,
            relays,
            secret,
        })
    }
}

/// Decodes the percent-escapes a `bunker://` query actually contains.
///
/// Hand-rolled rather than pulling a URL crate for it: the alphabet here is
/// relay URLs, so `%3A` and `%2F` are essentially all that appears, and a
/// dependency added for two escapes is a dependency to justify (CLAUDE.md §4.9).
/// An invalid escape is left as written rather than dropped — the relay check
/// then refuses it, which is better than silently producing a different URL.
fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            let hex = &input[index + 1..index + 3];
            if let Ok(byte) = u8::from_str_radix(hex, 16) {
                out.push(byte);
                index += 3;
                continue;
            }
        }
        out.push(bytes[index]);
        index += 1;
    }
    String::from_utf8(out).unwrap_or_else(|_| input.to_owned())
}

/// Parses a 32-byte hex pubkey and checks it is a curve point.
fn parse_pubkey(hex_str: &str) -> crate::Result<PublicKey> {
    let bad = || crate::Error::MalformedBunkerUrl;
    let bytes = hex::decode(hex_str).map_err(|_| bad())?;
    let array: [u8; 32] = bytes.try_into().map_err(|_| bad())?;

    // Checked here rather than at first use. A pubkey that is not on the curve
    // cannot receive an encrypted request, and finding that out at paste time is
    // the difference between "that link is wrong" and a silent failure later.
    secp256k1::XOnlyPublicKey::from_byte_array(array).map_err(|_| bad())?;
    Ok(PublicKey::from_bytes(array))
}
