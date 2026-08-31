//! The minimal nostr event shape that signing operates on.
//!
//! Deliberately small, and deliberately here rather than in `ghostr-nostr`:
//! [`Signer`](crate::Signer) needs something to sign, and `ghostr-crypto` cannot
//! depend on `ghostr-nostr` without inverting the dependency direction. The
//! relay codec, subscription handling, and Ghostr's own event kinds live in
//! `ghostr-nostr`, which depends on this.

use ghostr_core::hash::Hash32;
use ghostr_core::identity::PublicKey;
use serde::{Deserialize, Serialize};

/// A nostr event before it has been signed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnsignedEvent {
    /// Author.
    pub pubkey: PublicKey,
    /// Seconds since the Unix epoch, as nostr requires.
    pub created_at: u64,
    /// Event kind.
    pub kind: u16,
    /// Tags, each a list of strings.
    pub tags: Vec<Vec<String>>,
    /// Content. Ciphertext for every private Ghostr kind (SPEC I9).
    pub content: String,
}

impl UnsignedEvent {
    /// Computes the NIP-01 event id.
    ///
    /// The id is `sha256` of a canonical JSON array — this is nostr's rule, not
    /// ours, and it is the one place in the tree where a hash is taken over JSON
    /// rather than canonical CBOR. Keep the two straight: this hash is for
    /// protocol interoperability, never for the commitment chain.
    #[must_use]
    pub fn id(&self) -> Hash32 {
        use sha2::{Digest as _, Sha256};

        Hash32::from_bytes(Sha256::digest(self.serialized()).into())
    }

    /// The exact bytes NIP-01 hashes.
    ///
    /// Separate from [`UnsignedEvent::id`] so a test can read them. The id is
    /// a digest, and a digest tells you nothing about *why* it is wrong.
    ///
    /// NIP-01 fixes the shape: a six-element array, no whitespace, in this
    /// order, with a named escaping table for the content. `serde_json`
    /// produces exactly that — verified against the table in
    /// `the_escaping_matches_the_nip01_table` — which is why the array is built
    /// as JSON values rather than concatenated by hand.
    fn serialized(&self) -> Vec<u8> {
        let array = serde_json::json!([
            0,
            self.pubkey.to_hex(),
            self.created_at,
            self.kind,
            self.tags,
            self.content,
        ]);
        // Cannot fail: every branch is a plain JSON type, and the sink is a
        // `Vec`. There is no IO to fail and no custom `Serialize` to refuse.
        serde_json::to_vec(&array).unwrap_or_default()
    }
}

/// A BIP-340 Schnorr signature.
///
/// Serialized as lowercase hex rather than as a byte array: that is the form
/// nostr puts on the wire, and serde has no array impls past 32 elements anyway.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Signature([u8; 64]);

impl Serialize for Signature {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for Signature {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use serde::de::Error as _;

        let text = String::deserialize(deserializer)?;
        // Exactly 128 digits. A shorter one left-padded with zeroes would be a
        // different signature that a lenient parser would silently accept.
        if text.len() != 128 {
            return Err(D::Error::custom("a signature is 128 hex digits"));
        }
        let raw = hex::decode(&text).map_err(|_| D::Error::custom("not hex"))?;
        let bytes: [u8; 64] = raw
            .try_into()
            .map_err(|_| D::Error::custom("a signature is 64 bytes"))?;
        Ok(Self(bytes))
    }
}

impl Signature {
    /// Wraps 64 raw bytes.
    #[must_use]
    pub fn from_bytes(bytes: [u8; 64]) -> Self {
        Self(bytes)
    }

    /// The raw bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }

    /// Lowercase hex.
    #[must_use]
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl core::fmt::Debug for Signature {
    /// Prints the signature in full.
    ///
    /// Unlike everything else in this crate that hand-writes `Debug` to redact:
    /// a signature is public by construction — it goes on a relay for anyone to
    /// read — and a redacted one would make a failing event impossible to
    /// diagnose from a log.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.to_hex())
    }
}

/// A signed nostr event, ready to publish.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedEvent {
    /// The event id.
    pub id: Hash32,
    /// The unsigned body.
    #[serde(flatten)]
    pub event: UnsignedEvent,
    /// The signature over [`SignedEvent::id`].
    pub sig: Signature,
}

impl SignedEvent {
    /// Verifies that the id matches the body and the signature matches the id.
    ///
    /// Both halves matter. Checking the signature alone would accept an event
    /// whose id was computed over different content.
    ///
    /// # Errors
    ///
    /// Returns [`Error::BadSignature`](crate::Error::BadSignature) if either
    /// check fails.
    pub fn verify(&self) -> crate::Result<()> {
        // The id first. A signature that verifies over an id computed from
        // different content is a valid signature on the wrong event, and
        // checking only the signature is exactly how that gets through.
        if self.event.id() != self.id {
            return Err(crate::Error::BadSignature);
        }
        crate::nip06::verify(&self.event.pubkey, self.id.as_bytes(), &self.sig)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A concrete event, for reading the serialization back.
    fn event() -> UnsignedEvent {
        UnsignedEvent {
            pubkey: PublicKey::from_bytes([0x11; 32]),
            created_at: 1_673_347_337,
            kind: 1,
            tags: vec![
                vec!["e".to_owned(), "abc".to_owned()],
                vec!["p".to_owned(), "def".to_owned()],
            ],
            content: "Walletless zaps?".to_owned(),
        }
    }

    /// The serialization, spelled out.
    ///
    /// Checked against the structure NIP-01 states rather than against a hash
    /// somebody pasted: the digest of the wrong bytes is still a digest, and it
    /// says nothing about which field is in the wrong place. This is the form
    /// the NIP prints — `[0, pubkey, created_at, kind, tags, content]`, no
    /// whitespace — and the id below is its sha256 and nothing else.
    #[test]
    fn the_serialization_is_the_array_nip01_prints() {
        let serialized = String::from_utf8(event().serialized()).expect("utf-8");
        assert_eq!(
            serialized,
            concat!(
                "[0,",
                "\"1111111111111111111111111111111111111111111111111111111111111111\",",
                "1673347337,",
                "1,",
                "[[\"e\",\"abc\"],[\"p\",\"def\"]],",
                "\"Walletless zaps?\"]"
            )
        );
    }

    /// And the id is the sha256 of exactly those bytes.
    #[test]
    fn the_id_is_the_digest_of_the_serialization() {
        use sha2::{Digest as _, Sha256};

        let event = event();
        assert_eq!(
            event.id().to_hex(),
            hex::encode(Sha256::digest(event.serialized()))
        );
    }

    /// NIP-01 names seven characters that must be escaped and says every other
    /// character is included verbatim. Two implementations that disagree here
    /// compute different ids for the same event, and neither can read the
    /// other's — so the table is checked rather than assumed.
    #[test]
    fn the_escaping_matches_the_nip01_table() {
        let escaped = |content: &str| {
            let mut e = event();
            e.content = content.to_owned();
            let s = String::from_utf8(e.serialized()).expect("utf-8");
            let start = s.rfind('"').and_then(|_| s.rfind(",\"")).expect("content");
            s[start + 2..s.len() - 2].to_owned()
        };

        for (raw, expected) in [
            ("\u{0A}", "\\n"),
            ("\u{22}", "\\\""),
            ("\u{5C}", "\\\\"),
            ("\u{0D}", "\\r"),
            ("\u{09}", "\\t"),
            ("\u{08}", "\\b"),
            ("\u{0C}", "\\f"),
        ] {
            assert_eq!(escaped(raw), expected, "escaping {raw:?}");
        }

        // Everything else verbatim, which is what keeps a Thai journal and an
        // emoji hashing the same here as everywhere else.
        for verbatim in ["ก", "🦄", "a"] {
            assert_eq!(escaped(verbatim), verbatim);
        }
    }

    /// The round trip that matters: a real key signs, and the signature checks
    /// against the id the event computes for itself.
    #[test]
    fn a_signed_event_verifies_against_its_own_id() {
        use crate::nip06::{MasterKey, Mnemonic};
        use crate::secret::SecretString;
        use ghostr_core::identity::Account;

        // The NIP-06 vector's mnemonic, so the key is one the suite already
        // pins elsewhere.
        let mnemonic = Mnemonic::parse(SecretString::new(
            "leader monkey parrot ring guide accident before fence cannon height naive bean"
                .to_owned(),
        ))
        .expect("parse");
        let key = MasterKey::from_seed(&mnemonic.to_seed(None).expect("seed"))
            .expect("master")
            .derive_account(Account::Identity)
            .expect("derive");

        let mut unsigned = event();
        unsigned.pubkey = key.public;
        let id = unsigned.id();
        let signed = SignedEvent {
            id,
            event: unsigned,
            sig: key.sign(id.as_bytes()).expect("sign"),
        };
        signed.verify().expect("a freshly signed event verifies");
    }

    /// Checking the signature alone would accept an event whose id was computed
    /// over different content — a valid signature on the wrong event.
    #[test]
    fn an_event_whose_id_does_not_match_its_body_is_refused() {
        use crate::nip06::{MasterKey, Mnemonic};
        use crate::secret::SecretString;
        use ghostr_core::identity::Account;

        let mnemonic = Mnemonic::parse(SecretString::new(
            "leader monkey parrot ring guide accident before fence cannon height naive bean"
                .to_owned(),
        ))
        .expect("parse");
        let key = MasterKey::from_seed(&mnemonic.to_seed(None).expect("seed"))
            .expect("master")
            .derive_account(Account::Identity)
            .expect("derive");

        let mut unsigned = event();
        unsigned.pubkey = key.public;
        let id = unsigned.id();
        let sig = key.sign(id.as_bytes()).expect("sign");

        // The signature and the id still agree; the *body* no longer does.
        let mut tampered = unsigned;
        tampered.content = "something else entirely".to_owned();
        let signed = SignedEvent {
            id,
            event: tampered,
            sig,
        };
        assert!(matches!(signed.verify(), Err(crate::Error::BadSignature)));
    }

    /// The id covers every field. Changing any of them must change it, or an
    /// event could be rewritten in flight and keep its signature.
    #[test]
    fn every_field_is_inside_the_id() {
        let base = event();
        let original = base.id();

        let mut changed = base.clone();
        changed.created_at += 1;
        assert_ne!(changed.id(), original, "created_at");

        let mut changed = base.clone();
        changed.kind = 2;
        assert_ne!(changed.id(), original, "kind");

        let mut changed = base.clone();
        changed.content.push('!');
        assert_ne!(changed.id(), original, "content");

        let mut changed = base.clone();
        changed.tags.push(vec!["t".to_owned(), "x".to_owned()]);
        assert_ne!(changed.id(), original, "tags");

        let mut changed = base;
        changed.pubkey = PublicKey::from_bytes([9u8; 32]);
        assert_ne!(changed.id(), original, "pubkey");
    }

    /// Tag order is part of the id: reordering must not preserve it, or two
    /// different events would share one.
    #[test]
    fn tag_order_is_inside_the_id() {
        let base = event();
        let mut reordered = base.clone();
        reordered.tags.reverse();
        assert_ne!(reordered.id(), base.id());
    }

    /// Signatures are hex on the wire, and round-trip through serde.
    #[test]
    fn a_signature_round_trips_as_hex() {
        let sig = Signature::from_bytes([0xAB; 64]);
        let json = serde_json::to_string(&sig).expect("serialize");
        assert_eq!(json, format!("\"{}\"", "ab".repeat(64)));
        assert_eq!(
            serde_json::from_str::<Signature>(&json).expect("deserialize"),
            sig
        );
    }

    /// A short signature left-padded with zeroes is a different signature, and
    /// a lenient parser would silently accept it.
    #[test]
    fn a_malformed_signature_is_refused() {
        for bad in [
            "\"\"",
            "\"abcd\"",
            "\"zz\"",
            &format!("\"{}\"", "ab".repeat(63)),
        ] {
            assert!(
                serde_json::from_str::<Signature>(bad).is_err(),
                "accepted {bad}"
            );
        }
    }
}
