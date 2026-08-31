//! NIP-44 v2 payload encryption.
//!
//! Used for two things that look the same on the wire and mean different things:
//! ordinary encryption to another party, and **self-encryption** — deriving the
//! conversation key from one's own keypair — which is how Ghostr stores private
//! app data on relays that can never read it (SPEC §10.3).
//!
//! # What this does not hide
//!
//! NIP-44 encrypts content. It does not hide the author pubkey, the event kind,
//! the `d` tag, the `created_at`, or the ciphertext length. A relay sees all of
//! those and can infer a great deal from the pattern alone — a daily cadence of
//! same-kind events says "this person is alive, journaling, and stopped on the
//! 14th" (THREAT_MODEL §T2). [`pad_to_bucket`] blunts the length signal;
//! NIP-59 gift wrap, in `ghostr-nostr`, is what hides the rest.
//!
//! # Not ChaCha20-Poly1305
//!
//! NIP-44 v2 is **ChaCha20 without Poly1305**, authenticated instead by
//! HMAC-SHA256 over `nonce || ciphertext`. Reaching for the AEAD because the
//! name is close would produce payloads no other client can read.
//!
//! # Everything here is checked against the reference vectors
//!
//! `tests/nip44_vectors.rs` runs all 128 cases from the NIPs reference suite,
//! vendored unmodified. That includes the twelve `invalid/decrypt` cases, which
//! are the ones worth reading: they are the shapes an attacker sends.

use base64ct::{Base64, Encoding as _};
use chacha20::ChaCha20;
use chacha20::cipher::{KeyIvInit as _, StreamCipher as _};
use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::secret::SecretBytes;

/// The NIP-44 version this build implements.
pub const VERSION: u8 = 2;

/// The salt that separates NIP-44 v2 from every other use of this ECDH output.
const SALT: &[u8] = b"nip44-v2";

/// The longest plaintext NIP-44 admits, in bytes.
///
/// The padded form carries its length in a `u16`, so anything longer could not
/// state its own size.
pub const MAX_PLAINTEXT: usize = 65_535;

/// The shortest decoded payload that could contain anything: version, nonce,
/// one padding block, and the MAC.
const MIN_DECODED: usize = 99;
/// The longest decoded payload a maximal plaintext can produce.
const MAX_DECODED: usize = 65_603;

/// The same bounds, in base64 characters.
///
/// Checked separately, and that separation is the point: base64 is four
/// characters per three bytes, so bounding the encoded string by the decoded
/// ceiling silently rejects every long message — which round-trips fine on
/// short ones and fails only where it matters.
const MIN_ENCODED: usize = 132;
const MAX_ENCODED: usize = 87_472;

/// A NIP-44 conversation key: the ECDH-derived shared secret for a key pair.
///
/// For self-encryption both halves are the same identity, which yields a stable
/// key only that identity can derive.
#[derive(Debug)]
pub struct ConversationKey(SecretBytes<32>);

impl ConversationKey {
    /// Borrows the raw key.
    #[must_use]
    pub(crate) fn expose(&self) -> &[u8; 32] {
        self.0.expose()
    }

    /// Takes a conversation key that was derived elsewhere.
    ///
    /// Test-only, and compiled out otherwise: outside this crate a conversation
    /// key is something you derive, never something you supply. The
    /// reference-vector suite is the one caller, for the cases that state a key
    /// rather than deriving one — and `cfg(test)` is what keeps that true, since
    /// a supplied key skips the ECDH this type exists to enforce.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(SecretBytes::new(bytes))
    }

    /// Derives the conversation key between a secret key and a public key.
    ///
    /// The ECDH output is the shared point's **x-coordinate only**, unhashed —
    /// not the `secp256k1` crate's default `SharedSecret`, which hashes the
    /// compressed point and would produce a key no other NIP-44 client agrees
    /// with.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidPublicKey`](crate::Error::InvalidPublicKey) if
    /// either key is not a valid curve point.
    pub fn derive(
        secret: &[u8; 32],
        public: &ghostr_core::identity::PublicKey,
    ) -> crate::Result<Self> {
        use secp256k1::{PublicKey, SecretKey, XOnlyPublicKey};

        let secret =
            SecretKey::from_byte_array(*secret).map_err(|_| crate::Error::InvalidPublicKey)?;
        let x_only = XOnlyPublicKey::from_byte_array(*public.as_bytes())
            .map_err(|_| crate::Error::InvalidPublicKey)?;
        // NIP-44 fixes the parity at even: an x-only key names two points, and
        // the two would otherwise derive two different conversation keys.
        let public = PublicKey::from_x_only_public_key(x_only, secp256k1::Parity::Even);

        let point = secp256k1::ecdh::shared_secret_point(&public, &secret);
        let mut shared_x = [0u8; 32];
        shared_x.copy_from_slice(&point[..32]);

        let (prk, _) = hkdf::Hkdf::<Sha256>::extract(Some(SALT), &shared_x);
        let mut key = [0u8; 32];
        key.copy_from_slice(&prk);
        Ok(Self(SecretBytes::new(key)))
    }
}

/// The three keys one message uses, expanded from the conversation key.
///
/// Per-message, keyed by the nonce: two messages under one conversation key
/// never share a ChaCha20 key, so the keystream is never reused.
struct MessageKeys {
    chacha_key: [u8; 32],
    chacha_nonce: [u8; 12],
    hmac_key: [u8; 32],
}

impl MessageKeys {
    /// HKDF-expands the conversation key with the nonce as `info`.
    fn derive(key: &ConversationKey, nonce: &[u8; 32]) -> crate::Result<Self> {
        let hk = hkdf::Hkdf::<Sha256>::from_prk(key.expose())
            .map_err(|_| crate::Error::DecryptFailed)?;
        let mut okm = [0u8; 76];
        hk.expand(nonce, &mut okm)
            .map_err(|_| crate::Error::DecryptFailed)?;

        let mut chacha_key = [0u8; 32];
        let mut chacha_nonce = [0u8; 12];
        let mut hmac_key = [0u8; 32];
        chacha_key.copy_from_slice(&okm[..32]);
        chacha_nonce.copy_from_slice(&okm[32..44]);
        hmac_key.copy_from_slice(&okm[44..]);
        Ok(Self {
            chacha_key,
            chacha_nonce,
            hmac_key,
        })
    }

    /// `HMAC-SHA256(hmac_key, nonce || ciphertext)`.
    ///
    /// The nonce is associated data: without it, a payload's ciphertext could be
    /// lifted onto a different nonce and still authenticate.
    fn mac(&self, nonce: &[u8; 32], ciphertext: &[u8]) -> [u8; 32] {
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&self.hmac_key)
            .unwrap_or_else(|_| unreachable!("HMAC accepts any key length"));
        mac.update(nonce);
        mac.update(ciphertext);
        mac.finalize().into_bytes().into()
    }

    /// ChaCha20 in place, which is its own inverse.
    fn apply(&self, buffer: &mut [u8]) {
        let mut cipher = ChaCha20::new(&self.chacha_key.into(), &self.chacha_nonce.into());
        cipher.apply_keystream(buffer);
    }
}

/// Encrypts `plaintext` under a conversation key.
///
/// The nonce is supplied rather than generated here: entropy enters through
/// [`Rng`](ghostr_core::time::Rng) at the composition root, which is what makes
/// this reproducible under a fixed seed (ARCHITECTURE §4.7).
///
/// # Errors
///
/// Returns [`Error::DecryptFailed`](crate::Error::DecryptFailed) if the
/// plaintext is empty or longer than [`MAX_PLAINTEXT`] — the padded form states
/// its length in a `u16`, so neither can be represented.
pub fn encrypt(key: &ConversationKey, plaintext: &[u8], nonce: &[u8; 32]) -> crate::Result<String> {
    let padded = pad(plaintext)?;
    let keys = MessageKeys::derive(key, nonce)?;

    let mut ciphertext = padded;
    keys.apply(&mut ciphertext);
    let mac = keys.mac(nonce, &ciphertext);

    let mut payload = Vec::with_capacity(1 + 32 + ciphertext.len() + 32);
    payload.push(VERSION);
    payload.extend_from_slice(nonce);
    payload.extend_from_slice(&ciphertext);
    payload.extend_from_slice(&mac);
    Ok(Base64::encode_string(&payload))
}

/// Decrypts a NIP-44 payload.
///
/// The MAC is verified before decryption is attempted, and every failure mode
/// collapses to one error variant. A caller must not be able to distinguish a
/// bad MAC from bad padding from a wrong key: that distinction is precisely what
/// an oracle attack needs.
///
/// # Errors
///
/// Returns [`Error::DecryptFailed`](crate::Error::DecryptFailed) for any
/// failure, or
/// [`Error::UnsupportedVersion`](crate::Error::UnsupportedVersion) if the
/// payload declares a version this build does not implement.
pub fn decrypt(key: &ConversationKey, payload: &str) -> crate::Result<Vec<u8>> {
    // A leading `#` is NIP-44's reserved marker for a future, non-base64
    // encoding. Reported as an unsupported version rather than as a decrypt
    // failure, because it is a fact about the format and not about the key.
    if payload.as_bytes().first() == Some(&b'#') {
        return Err(crate::Error::UnsupportedVersion { version: 0 });
    }
    if payload.len() < MIN_ENCODED || payload.len() > MAX_ENCODED {
        return Err(crate::Error::DecryptFailed);
    }

    let raw = Base64::decode_vec(payload).map_err(|_| crate::Error::DecryptFailed)?;
    if raw.len() < MIN_DECODED || raw.len() > MAX_DECODED {
        return Err(crate::Error::DecryptFailed);
    }
    match raw[0] {
        VERSION => {}
        version => return Err(crate::Error::UnsupportedVersion { version }),
    }

    let mut nonce = [0u8; 32];
    nonce.copy_from_slice(&raw[1..33]);
    let (ciphertext, mac) = raw[33..].split_at(raw.len() - 33 - 32);

    let keys = MessageKeys::derive(key, &nonce)?;
    // Constant time, and before anything is decrypted. A comparison that
    // returned early would leak the MAC one byte at a time to anyone able to
    // retry, and retrying is free.
    if !constant_time_eq(&keys.mac(&nonce, ciphertext), mac) {
        return Err(crate::Error::DecryptFailed);
    }

    let mut padded = ciphertext.to_vec();
    keys.apply(&mut padded);
    unpad(&padded)
}

/// Whether two 32-byte digests match, without an early return.
fn constant_time_eq(a: &[u8; 32], b: &[u8]) -> bool {
    if b.len() != a.len() {
        return false;
    }
    let mut difference = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        difference |= x ^ y;
    }
    difference == 0
}

/// Prefixes the length and pads to the bucket.
fn pad(plaintext: &[u8]) -> crate::Result<Vec<u8>> {
    let len = plaintext.len();
    if len == 0 || len > MAX_PLAINTEXT {
        return Err(crate::Error::DecryptFailed);
    }
    let padded_len = pad_to_bucket(len);
    let mut out = Vec::with_capacity(2 + padded_len);
    out.extend_from_slice(&u16::try_from(len).unwrap_or(u16::MAX).to_be_bytes());
    out.extend_from_slice(plaintext);
    out.resize(2 + padded_len, 0);
    Ok(out)
}

/// Reads the length prefix back and checks the padding is the shape it claims.
///
/// The length check is not a formality: without it a payload could declare a
/// short length inside a long buffer, and two different paddings would decrypt
/// to the same plaintext — which is a malleability an attacker can use.
fn unpad(padded: &[u8]) -> crate::Result<Vec<u8>> {
    if padded.len() < 2 {
        return Err(crate::Error::DecryptFailed);
    }
    let len = usize::from(u16::from_be_bytes([padded[0], padded[1]]));
    let body = padded.get(2..2 + len).ok_or(crate::Error::DecryptFailed)?;
    if len == 0 || padded.len() != 2 + pad_to_bucket(len) {
        return Err(crate::Error::DecryptFailed);
    }
    Ok(body.to_vec())
}

/// Pads a plaintext length up to the next NIP-44 bucket.
///
/// Length is metadata. Without padding, a 40-word day and a 4000-word day are
/// trivially distinguishable to a relay operator watching one pubkey over time.
///
/// Buckets are coarse at first — everything up to 32 bytes looks the same — and
/// then grow with the message, so the leak is a *rough magnitude* rather than a
/// byte count.
#[must_use]
pub fn pad_to_bucket(len: usize) -> usize {
    if len <= 32 {
        return 32;
    }
    // The next power of two at or above `len`, then eighths of it. `len - 1`
    // rather than `len` so an exact power of two stays in its own bucket
    // instead of jumping to the next.
    let next_power = 1usize << (usize::BITS - (len - 1).leading_zeros());
    let chunk = if next_power <= 256 {
        32
    } else {
        next_power / 8
    };
    chunk * ((len - 1) / chunk + 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Round-tripping is the least a cipher can do, and the first thing to
    /// break when the key schedule is subtly wrong.
    #[test]
    fn a_payload_round_trips() {
        let key = ConversationKey::from_bytes([7u8; 32]);
        let nonce = [9u8; 32];
        let payload = encrypt(&key, b"met Nan at the tea shop", &nonce).expect("encrypt");
        assert_eq!(
            decrypt(&key, &payload).expect("decrypt"),
            b"met Nan at the tea shop"
        );
    }

    /// The wrong key must fail, and must fail the same way everything else
    /// does.
    #[test]
    fn the_wrong_key_fails_indistinguishably() {
        let payload =
            encrypt(&ConversationKey::from_bytes([7u8; 32]), b"x", &[9u8; 32]).expect("encrypt");
        assert!(matches!(
            decrypt(&ConversationKey::from_bytes([8u8; 32]), &payload),
            Err(crate::Error::DecryptFailed)
        ));
    }

    /// I8. A conversation key in a log line is every message under it.
    #[test]
    fn a_conversation_key_never_debug_prints_itself() {
        let key = ConversationKey::from_bytes([0xAB; 32]);
        let rendered = format!("{key:?}");
        assert!(!rendered.contains("ab"), "{rendered}");
        assert!(rendered.contains("redacted"));
    }

    /// Two messages under one conversation key must never share a ChaCha20
    /// key: the same keystream twice makes both recoverable.
    #[test]
    fn a_different_nonce_gives_a_different_keystream() {
        let key = ConversationKey::from_bytes([7u8; 32]);
        let a = MessageKeys::derive(&key, &[1u8; 32]).expect("a");
        let b = MessageKeys::derive(&key, &[2u8; 32]).expect("b");
        assert_ne!(a.chacha_key, b.chacha_key);
        assert_ne!(a.hmac_key, b.hmac_key);
    }

    /// A plaintext that cannot state its own length has no padded form.
    #[test]
    fn lengths_outside_the_representable_range_are_refused() {
        let key = ConversationKey::from_bytes([7u8; 32]);
        assert!(encrypt(&key, b"", &[9u8; 32]).is_err());
        assert!(encrypt(&key, &vec![0u8; MAX_PLAINTEXT + 1], &[9u8; 32]).is_err());
        assert!(encrypt(&key, &vec![0u8; MAX_PLAINTEXT], &[9u8; 32]).is_ok());
    }

    /// Flipping any byte of the ciphertext or the MAC must be caught. ChaCha20
    /// is malleable on its own — the HMAC is the only thing standing between a
    /// relay and a rewritten memory.
    #[test]
    fn a_tampered_payload_is_refused() {
        let key = ConversationKey::from_bytes([7u8; 32]);
        let payload = encrypt(&key, b"the lease is fine", &[9u8; 32]).expect("encrypt");
        let mut raw = Base64::decode_vec(&payload).expect("decode");

        for index in [0, 1, 40, raw.len() - 1] {
            let original = raw[index];
            raw[index] ^= 0x01;
            let tampered = Base64::encode_string(&raw);
            assert!(
                decrypt(&key, &tampered).is_err(),
                "a flipped byte at {index} was accepted"
            );
            raw[index] = original;
        }
    }
}

#[cfg(test)]
mod vectors {
    //! Every case in the NIP-44 v2 reference suite.
    //!
    //! `vectors/nip44.vectors.json` is vendored unmodified from the reference
    //! repository NIP-44 points at. CLAUDE.md §6 requires the vectors verbatim,
    //! and the reason is worth restating: a vector adjusted to match our output
    //! is not a test, it is a transcription of a bug — and this is the one file
    //! in the tree whose correctness other people's clients depend on.
    //!
    //! Run whole rather than sampled. The interesting cases are the twelve under
    //! `invalid/decrypt`, because those are the shapes an attacker sends: a
    //! lifted MAC, a padding that lies about its length, a version nobody
    //! implements.
    //!
    //! A unit test rather than one under `tests/`, because checking the message
    //! keys means seeing them — and the alternative was a public method that
    //! reveals a conversation key, which is a worse thing to have than a test in
    //! an unusual place.

    use ghostr_core::identity::PublicKey;
    use serde_json::Value;

    use super::*;

    /// The vendored suite, compiled in so the test cannot silently run on
    /// nothing.
    const VECTORS: &str = include_str!("../vectors/nip44.vectors.json");

    fn suite() -> Value {
        serde_json::from_str::<Value>(VECTORS).expect("the vendored vectors parse")["v2"].clone()
    }

    fn bytes(value: &Value) -> Vec<u8> {
        hex::decode(value.as_str().expect("a hex string")).expect("valid hex")
    }

    fn array32(value: &Value) -> [u8; 32] {
        bytes(value).try_into().expect("32 bytes")
    }

    /// The plaintext a case carries, which is either stated or described.
    fn plaintext(case: &Value) -> Vec<u8> {
        case.get("plaintext").map_or_else(
            || {
                // The long-message cases state a pattern and a repeat count
                // rather than sixty kilobytes of literal text.
                let pattern = case["pattern"].as_str().expect("a pattern");
                let repeat =
                    usize::try_from(case["repeat"].as_u64().expect("a count")).expect("fits");
                pattern.repeat(repeat).into_bytes()
            },
            |p| p.as_str().expect("a string").as_bytes().to_vec(),
        )
    }

    /// The x-only public key for a secret key, which the vectors state only as
    /// `sec2`.
    fn public_of(secret: &[u8; 32]) -> PublicKey {
        let secp = secp256k1::Secp256k1::new();
        let sk = secp256k1::SecretKey::from_byte_array(*secret).expect("a valid secret");
        let (x_only, _) = sk.x_only_public_key(&secp);
        PublicKey::from_bytes(x_only.serialize())
    }

    #[test]
    fn valid_get_conversation_key() {
        let cases = suite()["valid"]["get_conversation_key"].clone();
        let cases = cases.as_array().expect("an array");
        assert_eq!(cases.len(), 35, "the suite changed size");

        for (index, case) in cases.iter().enumerate() {
            let derived = ConversationKey::derive(
                &array32(&case["sec1"]),
                &PublicKey::from_bytes(array32(&case["pub2"])),
            )
            .unwrap_or_else(|e| panic!("case {index}: {e}"));
            assert_eq!(
                hex::encode(derived.expose()),
                case["conversation_key"].as_str().expect("a key"),
                "case {index}"
            );
        }
    }

    /// Expanding a conversation key and a nonce into the three message keys.
    /// This is where an off-by-one in the HKDF output would hide.
    #[test]
    fn valid_get_message_keys() {
        let group = suite()["valid"]["get_message_keys"].clone();
        let key = ConversationKey::from_bytes(array32(&group["conversation_key"]));
        let cases = group["keys"].as_array().expect("an array").clone();
        assert_eq!(cases.len(), 32, "the suite changed size");

        for (index, case) in cases.iter().enumerate() {
            let keys = MessageKeys::derive(&key, &array32(&case["nonce"])).expect("derive");
            assert_eq!(
                hex::encode(keys.chacha_key),
                case["chacha_key"].as_str().expect("key"),
                "case {index} chacha_key"
            );
            assert_eq!(
                hex::encode(keys.chacha_nonce),
                case["chacha_nonce"].as_str().expect("nonce"),
                "case {index} chacha_nonce"
            );
            assert_eq!(
                hex::encode(keys.hmac_key),
                case["hmac_key"].as_str().expect("hmac"),
                "case {index} hmac_key"
            );
        }
    }

    /// The padding table. Get this wrong and payloads are the right length for
    /// the wrong reason, which round-trips locally and fails against every
    /// other client.
    #[test]
    fn valid_calc_padded_len() {
        let cases = suite()["valid"]["calc_padded_len"].clone();
        let cases = cases.as_array().expect("an array");
        assert_eq!(cases.len(), 24, "the suite changed size");

        for case in cases {
            let pair = case.as_array().expect("a pair");
            let len = usize::try_from(pair[0].as_u64().expect("len")).expect("fits");
            let expected = usize::try_from(pair[1].as_u64().expect("padded")).expect("fits");
            assert_eq!(pad_to_bucket(len), expected, "length {len}");
        }
    }

    /// Encrypt to a stated payload, byte for byte, and decrypt back.
    ///
    /// Encrypting to the exact expected bytes is the strong direction: a
    /// round-trip alone would pass on a cipher that is merely self-consistent.
    #[test]
    fn valid_encrypt_decrypt() {
        let cases = suite()["valid"]["encrypt_decrypt"].clone();
        let cases = cases.as_array().expect("an array");
        assert_eq!(cases.len(), 10, "the suite changed size");

        for (index, case) in cases.iter().enumerate() {
            let key = ConversationKey::derive(
                &array32(&case["sec1"]),
                &public_of(&array32(&case["sec2"])),
            )
            .expect("derive");
            assert_eq!(
                hex::encode(key.expose()),
                case["conversation_key"].as_str().expect("key"),
                "case {index} conversation key"
            );

            let text = plaintext(case);
            let payload = encrypt(&key, &text, &array32(&case["nonce"])).expect("encrypt");
            assert_eq!(
                payload,
                case["payload"].as_str().expect("payload"),
                "case {index} payload"
            );

            // And the other direction, from the *stated* payload rather than
            // ours, so a matching pair of bugs cannot cancel out.
            assert_eq!(
                decrypt(&key, case["payload"].as_str().expect("payload")).expect("decrypt"),
                text,
                "case {index} decrypt"
            );
        }
    }

    /// The long messages, up to the 65535-byte ceiling. Checked by digest,
    /// because the vectors state one rather than sixty kilobytes of output.
    #[test]
    fn valid_encrypt_decrypt_long_msg() {
        use sha2::{Digest as _, Sha256};

        let cases = suite()["valid"]["encrypt_decrypt_long_msg"].clone();
        let cases = cases.as_array().expect("an array");
        assert_eq!(cases.len(), 3, "the suite changed size");

        for (index, case) in cases.iter().enumerate() {
            let key = ConversationKey::from_bytes(array32(&case["conversation_key"]));
            let text = plaintext(case);

            assert_eq!(
                hex::encode(Sha256::digest(&text)),
                case["plaintext_sha256"].as_str().expect("digest"),
                "case {index}: the vector's own plaintext did not reproduce"
            );

            let payload = encrypt(&key, &text, &array32(&case["nonce"])).expect("encrypt");
            assert_eq!(
                hex::encode(Sha256::digest(payload.as_bytes())),
                case["payload_sha256"].as_str().expect("digest"),
                "case {index} payload"
            );
            assert_eq!(decrypt(&key, &payload).expect("decrypt"), text);
        }
    }

    /// Lengths the padded form cannot state.
    #[test]
    fn invalid_encrypt_msg_lengths() {
        let cases = suite()["invalid"]["encrypt_msg_lengths"].clone();
        let cases = cases.as_array().expect("an array");
        assert_eq!(cases.len(), 4, "the suite changed size");

        let key = ConversationKey::from_bytes([7u8; 32]);
        for case in cases {
            let len = usize::try_from(case.as_u64().expect("a length")).expect("fits");
            assert!(
                encrypt(&key, &vec![b'a'; len], &[9u8; 32]).is_err(),
                "length {len} was accepted"
            );
        }
    }

    /// Keys that are not on the curve, or not in its order.
    #[test]
    fn invalid_get_conversation_key() {
        let cases = suite()["invalid"]["get_conversation_key"].clone();
        let cases = cases.as_array().expect("an array");
        assert_eq!(cases.len(), 8, "the suite changed size");

        for case in cases {
            let note = case["note"].as_str().unwrap_or("");
            let secret: Result<[u8; 32], _> = bytes(&case["sec1"]).try_into();
            let public: Result<[u8; 32], _> = bytes(&case["pub2"]).try_into();
            let refused = match (secret, public) {
                (Ok(secret), Ok(public)) => {
                    ConversationKey::derive(&secret, &PublicKey::from_bytes(public)).is_err()
                }
                // A key of the wrong length never reaches the curve at all.
                _ => true,
            };
            assert!(refused, "accepted a bad key: {note}");
        }
    }

    /// The shapes an attacker sends. Every one must be refused.
    #[test]
    fn invalid_decrypt() {
        let cases = suite()["invalid"]["decrypt"].clone();
        let cases = cases.as_array().expect("an array");
        assert_eq!(cases.len(), 12, "the suite changed size");

        for case in cases {
            let note = case["note"].as_str().unwrap_or("");
            let key = ConversationKey::from_bytes(array32(&case["conversation_key"]));
            let payload = case["payload"].as_str().expect("a payload");
            assert!(
                decrypt(&key, payload).is_err(),
                "accepted an invalid payload: {note}"
            );
        }
    }
}
