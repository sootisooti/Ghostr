//! Encoding Ghostr payloads into nostr events, and decoding them back.
//!
//! # Disclosure is enforced by construction (SPEC I10)
//!
//! [`GhostNoteBuilder`] is the only way to build a ghost-authored kind-1 event,
//! and it always emits the disclosure tags. There is no method to omit them and
//! no constructor that bypasses it, so "a ghost note without disclosure cannot
//! be constructed" is a property of the API rather than a rule contributors are
//! asked to remember.
//!
//! A ghost that can pass as its principal without a machine-readable marker is
//! an impersonation tool, which is a different product than this one.

use ghostr_core::identity::{KeyRef, PublicKey};
use ghostr_crypto::Signer;
use ghostr_crypto::event::UnsignedEvent;
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::kinds::Kind;

/// The tag marking an event as ghost-authored.
pub const DISCLOSURE_TAG: [&str; 3] = ["ghostr", "v1", "ghost-authored"];

/// The `client` tag value.
pub const CLIENT_TAG_VALUE: &str = "ghostr";

/// Encodes a payload into an unsigned event, encrypting if the kind requires it.
///
/// # The signer, and why the author is not a parameter
///
/// The scaffold took an `author: &PublicKey` and no key, which cannot work: a
/// private kind has to be encrypted, and encryption needs a secret. Taking the
/// [`Signer`] instead closes that hole and removes a second one — an author
/// passed separately from the key that encrypts can disagree with it, producing
/// an event addressed to a pubkey that cannot read it.
///
/// `nonce` is a parameter for the reason every other nonce in this tree is
/// (CLAUDE.md §6): entropy belongs to the composition root. It must be fresh per
/// event — NIP-44 derives its keystream from it.
///
/// # Errors
///
/// Returns [`Error::WrongSigningAccount`](crate::Error::WrongSigningAccount) if
/// `key` is not the account SPEC §8.1 assigns to this kind,
/// [`Error::MalformedPayload`](crate::Error::MalformedPayload) if `payload` does
/// not serialize, and [`Error::Crypto`](crate::Error::Crypto) if the keystore is
/// locked or encryption fails.
pub async fn encode<T: Serialize>(
    signer: &dyn Signer,
    key: KeyRef,
    kind: Kind,
    identifier: &str,
    created_at: u64,
    payload: &T,
    nonce: [u8; 32],
) -> crate::Result<UnsignedEvent> {
    // SPEC §8.1: the kind decides which account signs, not the caller. An anchor
    // receipt encoded under the identity key would tie the chain to the identity
    // — precisely the link the separate anchor account exists to break — and it
    // would do so silently, since the event is otherwise well formed.
    if key.account != kind.signing_account() {
        return Err(crate::Error::WrongSigningAccount {
            kind: kind.as_u16(),
        });
    }

    let author = signer.public_key(key)?;

    // JSON, not canonical CBOR. Neither of CLAUDE.md §5's two codecs applies
    // here: nostr's `content` is a string field and this value is never hashed
    // by us — the event id covers it, and that id is taken over JSON anyway.
    let plaintext = serde_json::to_string(payload).map_err(|_| crate::Error::MalformedPayload {
        kind: kind.as_u16(),
    })?;

    let content = if kind.is_encrypted() {
        // Self-encryption: the recipient is the author. These kinds exist so the
        // user's own other devices can restore from a relay, and a relay that
        // holds them must learn nothing (SPEC I9).
        signer
            .nip44_encrypt(key, &author, plaintext.as_bytes(), nonce)
            .await?
    } else {
        plaintext
    };

    Ok(UnsignedEvent {
        pubkey: author,
        created_at,
        kind: kind.as_u16(),
        tags: vec![vec!["d".to_owned(), kind.d_tag(identifier)]],
        content,
    })
}

/// Decodes an event into a payload.
///
/// The event's signature and id must already have been verified: relay-supplied
/// events are untrusted input, and decoding one that was not checked is how a
/// forged manifest gets treated as real.
///
/// # Errors
///
/// Returns [`Error::MalformedPayload`](crate::Error::MalformedPayload) if the
/// content does not decode as `T`.
pub async fn decode<T: DeserializeOwned>(
    signer: &dyn Signer,
    key: KeyRef,
    kind: Kind,
    event: &UnsignedEvent,
) -> crate::Result<T> {
    decode_inner(signer, key, kind, event, false).await
}

/// Decodes a payload from either the 3178x event or its NIP-78 mirror.
///
/// The point of the mirror is that a reader who cannot resolve 3178x still gets
/// the same bytes (SPEC Q3), and a reader that refuses kind 30078 is not such a
/// reader. [`decode`] stays strict: a caller that asked for a footage record
/// and got application data should hear about it.
///
/// The numeric kind is the only check that relaxes. The `d` tag still has to
/// name `kind`, and it is the stronger of the two: `ghostr/v1/footage/7` says
/// what an event is regardless of the number it was filed under, which is
/// exactly why the block being unclaimed is survivable.
///
/// # Errors
///
/// Returns [`Error::MalformedPayload`](crate::Error::MalformedPayload) if the
/// event is neither form, if its `d` tag names another kind, or if the
/// plaintext does not deserialise.
pub async fn decode_mirrored<T: DeserializeOwned>(
    signer: &dyn Signer,
    key: KeyRef,
    kind: Kind,
    event: &UnsignedEvent,
) -> crate::Result<T> {
    decode_inner(signer, key, kind, event, true).await
}

async fn decode_inner<T: DeserializeOwned>(
    signer: &dyn Signer,
    key: KeyRef,
    kind: Kind,
    event: &UnsignedEvent,
    accept_mirror: bool,
) -> crate::Result<T> {
    let kind_ok = event.kind == kind.as_u16()
        || (accept_mirror && event.kind == crate::kinds::NIP78_APP_DATA);
    if !kind_ok {
        return Err(crate::Error::MalformedPayload {
            kind: kind.as_u16(),
        });
    }

    // The `d` tag must name this kind too. Without the check, an event of the
    // right numeric kind carrying another application's `d` tag would be decoded
    // as ours — and on an unclaimed kind block (SPEC Q3) that is not a
    // hypothetical, it is the expected collision.
    //
    // For a mirror it is not a second check but the *only* one: kind 30078 is
    // shared application data that anyone may publish, so nothing but this tag
    // distinguishes a Ghostr footage from another application's settings blob.
    let d_tag = first_tag_value(event, "d").ok_or(crate::Error::MalformedPayload {
        kind: kind.as_u16(),
    })?;
    match Kind::from_d_tag(d_tag) {
        Some((found, _)) if found == kind => {}
        _ => {
            return Err(crate::Error::MalformedPayload {
                kind: kind.as_u16(),
            });
        }
    }

    let plaintext = if kind.is_encrypted() {
        signer
            .nip44_decrypt(key, &event.pubkey, &event.content)
            .await?
    } else {
        event.content.clone().into_bytes()
    };

    serde_json::from_slice(&plaintext).map_err(|_| crate::Error::MalformedPayload {
        kind: kind.as_u16(),
    })
}

/// The first value of the first tag with this name.
///
/// Nostr tags are `[name, value, ...]`. First match wins: a second `d` tag is
/// not a correction, and letting a later one override would let a relay change
/// which record an event replaces by appending to it.
#[must_use]
fn first_tag_value<'a>(event: &'a UnsignedEvent, name: &str) -> Option<&'a str> {
    event
        .tags
        .iter()
        .find(|t| t.first().is_some_and(|n| n == name))
        .and_then(|t| t.get(1))
        .map(String::as_str)
}

/// Builds the NIP-78 (kind 30078) mirror of an event.
///
/// Published alongside the 3178x form so that correctness never depends on an
/// unclaimed kind block being ours (SPEC Q3).
///
/// # Errors
///
/// Returns an error if the source event cannot be re-encoded.
pub fn mirror_as_nip78(event: &UnsignedEvent) -> crate::Result<UnsignedEvent> {
    // Only Ghostr's own kinds get mirrored. A kind-1 ghost note republished as
    // application data would be a second copy with the disclosure tags carried
    // into a context where nothing reads them.
    let kind = Kind::ALL
        .into_iter()
        .find(|k| k.as_u16() == event.kind)
        .ok_or(crate::Error::NotMirrorable { kind: event.kind })?;

    // The `d` tag must already be ours: `(kind, pubkey, d)` addresses a
    // replaceable event, and the mirror has to answer to the same `d` for the
    // fallback to find anything.
    let d_tag =
        first_tag_value(event, "d").ok_or(crate::Error::NotMirrorable { kind: event.kind })?;
    if Kind::from_d_tag(d_tag).map(|(k, _)| k) != Some(kind) {
        return Err(crate::Error::NotMirrorable { kind: event.kind });
    }

    Ok(UnsignedEvent {
        kind: crate::kinds::NIP78_APP_DATA,
        // Content byte-identical, tags included. The mirror exists so a reader
        // who cannot resolve 3178x still gets the same bytes; re-encoding here
        // would let the two copies drift, and only one of them is anchored.
        ..event.clone()
    })
}

/// Builds ghost-authored kind-1 notes, disclosure tags included.
///
/// Every constructed event carries `["ghostr","v1","ghost-authored"]`, a `p` tag
/// naming the principal, and `["client","ghostr"]`.
#[derive(Debug)]
pub struct GhostNoteBuilder {
    ghost_pubkey: PublicKey,
    principal: PublicKey,
    content: String,
}

impl GhostNoteBuilder {
    /// Starts a note.
    ///
    /// Requires the principal's pubkey up front, so a note that does not name
    /// who it is speaking for cannot be started, let alone finished.
    #[must_use]
    pub fn new(ghost_pubkey: PublicKey, principal: PublicKey) -> Self {
        Self {
            ghost_pubkey,
            principal,
            content: String::new(),
        }
    }

    /// Sets the note text.
    #[must_use]
    pub fn content(mut self, text: impl Into<String>) -> Self {
        self.content = text.into();
        self
    }

    /// Builds the event with its disclosure tags.
    ///
    /// # Errors
    ///
    /// Returns an error if the content is empty.
    pub fn build(self, created_at: u64) -> crate::Result<UnsignedEvent> {
        if self.content.trim().is_empty() {
            return Err(crate::Error::EmptyNote);
        }

        Ok(UnsignedEvent {
            pubkey: self.ghost_pubkey,
            created_at,
            kind: crate::kinds::standard::TEXT_NOTE,
            // I10: emitted here and nowhere else. There is no setter for tags
            // and no other constructor, so an undisclosed ghost note is not
            // something a caller can build wrong — it is something they cannot
            // express.
            tags: vec![
                DISCLOSURE_TAG.map(str::to_owned).to_vec(),
                vec!["p".to_owned(), self.principal.to_hex()],
                vec!["client".to_owned(), CLIENT_TAG_VALUE.to_owned()],
            ],
            content: self.content,
        })
    }
}

/// Whether an event from a relay carries valid ghost disclosure tags.
///
/// For inbound events, where a third party may have published something claiming
/// to be a ghost without disclosing it. Outbound events cannot lack the tags.
#[must_use]
pub fn has_disclosure(event: &UnsignedEvent) -> bool {
    let marked = event.tags.iter().any(|t| t.as_slice() == DISCLOSURE_TAG);

    // The marker alone is not disclosure. "This is a ghost" without "of whom"
    // tells a reader nothing they can act on, and a `p` tag that is not a pubkey
    // is decoration — so the value is parsed, not merely counted.
    let names_principal =
        first_tag_value(event, "p").is_some_and(|hex| PublicKey::from_hex(hex).is_ok());

    marked && names_principal
}

#[cfg(test)]
mod tests {
    use ghostr_core::identity::Account;
    use ghostr_crypto::kdf::Argon2Params;
    use ghostr_crypto::keystore::{FileKeystore, KEYSTORE_FILENAME};
    use ghostr_crypto::nip06::Mnemonic;
    use ghostr_crypto::secret::SecretString;
    use ghostr_crypto::signer::Keystore;
    use serde::Deserialize;

    use super::*;

    const PHRASE: &str =
        "leader monkey parrot ring guide accident before fence cannon height naive bean";

    /// A real keystore, unlocked.
    ///
    /// Cheap Argon2 parameters, and deliberately spelled out rather than reached
    /// through a named "fast mode": the fields are public, so this costs no new
    /// API surface, and a helper called `insecure` reachable from a config file
    /// is the downgrade attack `ghostr-crypto` refuses to ship.
    fn keystore(dir: &std::path::Path) -> FileKeystore {
        let mnemonic = Mnemonic::parse(SecretString::new(PHRASE.to_owned())).expect("parse");
        let pass = SecretString::new("hunter2 hunter2 hunter2".to_owned());
        let mut ks = FileKeystore::create(
            &dir.join(KEYSTORE_FILENAME),
            &mnemonic,
            &pass,
            [1u8; 16],
            [2u8; 24],
            Argon2Params {
                memory_kib: 8,
                iterations: 1,
                lanes: 1,
            },
        )
        .expect("create");
        ks.unlock(pass).expect("unlock");
        ks
    }

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct Footage {
        date: String,
        summary: String,
    }

    fn footage() -> Footage {
        Footage {
            date: "2026-08-27".to_owned(),
            summary: "walked to the river and did not answer the phone".to_owned(),
        }
    }

    #[tokio::test]
    async fn a_private_kind_round_trips_and_the_relay_learns_nothing() {
        let dir = tempfile::tempdir().expect("tempdir");
        let ks = keystore(dir.path());
        let key = ks.key_ref(Account::Data).expect("key_ref");

        let event = encode(
            &ks,
            key,
            Kind::FootageRecord,
            "2026-08-27",
            1_756_252_800,
            &footage(),
            [42u8; 32],
        )
        .await
        .expect("encode");

        // I9: what a relay stores must carry no readable identity data. The
        // date is in the `d` tag by design — it is what makes the record
        // addressable — but nothing from the body may appear.
        assert!(!event.content.contains("river"));
        assert!(!event.content.contains("phone"));
        assert!(!event.content.contains("summary"));
        assert_eq!(event.kind, 31783);
        assert_eq!(event.tags, [["d", "ghostr/v1/footage/2026-08-27"]]);

        let back: Footage = decode(&ks, key, Kind::FootageRecord, &event)
            .await
            .expect("decode");
        assert_eq!(back, footage());
    }

    #[tokio::test]
    async fn a_public_kind_is_left_readable() {
        // A manifest nobody can read is not an attestation. The complement of
        // I9: these kinds are public *because* being public is their function.
        let dir = tempfile::tempdir().expect("tempdir");
        let ks = keystore(dir.path());
        let key = ks.key_ref(Account::Identity).expect("key_ref");

        let event = encode(
            &ks,
            key,
            Kind::GhostManifest,
            "current",
            1_756_252_800,
            &footage(),
            [42u8; 32],
        )
        .await
        .expect("encode");

        assert!(event.content.contains("river"));
        let back: Footage = decode(&ks, key, Kind::GhostManifest, &event)
            .await
            .expect("decode");
        assert_eq!(back, footage());
    }

    #[tokio::test]
    async fn encoding_under_the_wrong_account_is_refused() {
        // SPEC §8.1. Encoding an anchor receipt under the identity key produces
        // a perfectly valid event that quietly links the chain to the identity.
        let dir = tempfile::tempdir().expect("tempdir");
        let ks = keystore(dir.path());
        let identity = ks.key_ref(Account::Identity).expect("key_ref");

        let result = encode(
            &ks,
            identity,
            Kind::AnchorReceipt,
            "42",
            1_756_252_800,
            &footage(),
            [42u8; 32],
        )
        .await;

        assert!(matches!(
            result,
            Err(crate::Error::WrongSigningAccount { kind: 31784 })
        ));
    }

    #[tokio::test]
    async fn a_foreign_d_tag_on_our_kind_is_refused() {
        // The SPEC Q3 collision, arriving from a relay: right number, wrong app.
        let dir = tempfile::tempdir().expect("tempdir");
        let ks = keystore(dir.path());
        let key = ks.key_ref(Account::Identity).expect("key_ref");

        let mut event = encode(
            &ks,
            key,
            Kind::GhostManifest,
            "current",
            1_756_252_800,
            &footage(),
            [42u8; 32],
        )
        .await
        .expect("encode");
        event.tags = vec![vec![
            "d".to_owned(),
            "someapp/v1/manifest/current".to_owned(),
        ]];

        let result: crate::Result<Footage> = decode(&ks, key, Kind::GhostManifest, &event).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn decoding_as_the_wrong_kind_is_refused() {
        let dir = tempfile::tempdir().expect("tempdir");
        let ks = keystore(dir.path());
        let key = ks.key_ref(Account::Identity).expect("key_ref");

        let event = encode(
            &ks,
            key,
            Kind::GhostManifest,
            "current",
            1_756_252_800,
            &footage(),
            [42u8; 32],
        )
        .await
        .expect("encode");

        let result: crate::Result<Footage> = decode(&ks, key, Kind::RevocationNotice, &event).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn a_second_d_tag_cannot_redirect_the_record() {
        // A relay appending a tag must not change which record an event
        // replaces. First match wins, so the appended one is inert.
        let dir = tempfile::tempdir().expect("tempdir");
        let ks = keystore(dir.path());
        let key = ks.key_ref(Account::Identity).expect("key_ref");

        let mut event = encode(
            &ks,
            key,
            Kind::GhostManifest,
            "current",
            1_756_252_800,
            &footage(),
            [42u8; 32],
        )
        .await
        .expect("encode");
        event
            .tags
            .push(vec!["d".to_owned(), "ghostr/v1/revocation/x".to_owned()]);

        let back: Footage = decode(&ks, key, Kind::GhostManifest, &event)
            .await
            .expect("decode");
        assert_eq!(back, footage());
    }

    #[tokio::test]
    async fn two_encodes_of_one_payload_differ() {
        // Distinct nonces must give distinct ciphertext. Equal output would mean
        // the nonce is not reaching the keystream, and a relay could tell that
        // today's footage repeats last week's.
        let dir = tempfile::tempdir().expect("tempdir");
        let ks = keystore(dir.path());
        let key = ks.key_ref(Account::Data).expect("key_ref");

        let one = encode(&ks, key, Kind::QuestSet, "a", 1, &footage(), [1u8; 32])
            .await
            .expect("encode");
        let two = encode(&ks, key, Kind::QuestSet, "a", 1, &footage(), [2u8; 32])
            .await
            .expect("encode");
        assert_ne!(one.content, two.content);
    }

    // -----------------------------------------------------------------------
    // Disclosure (SPEC I10)
    // -----------------------------------------------------------------------

    fn pubkeys() -> (PublicKey, PublicKey) {
        let ghost =
            PublicKey::from_hex("3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d")
                .expect("hex");
        let principal =
            PublicKey::from_hex("7e7e9c42a91bfef19fa929e5fda1b72e0ebc1a4c1141673e2794234d86addf4e")
                .expect("hex");
        (ghost, principal)
    }

    #[test]
    fn a_ghost_note_cannot_be_built_without_disclosure() {
        // The M3 exit criterion. There is no builder method that omits the tags
        // and no other constructor, so this is the only shape `build` produces.
        let (ghost, principal) = pubkeys();
        let event = GhostNoteBuilder::new(ghost, principal)
            .content("I think I'd have said no to that.")
            .build(1_756_252_800)
            .expect("build");

        assert_eq!(event.kind, 1);
        assert!(has_disclosure(&event));
        assert_eq!(
            event.tags,
            [
                vec!["ghostr", "v1", "ghost-authored"],
                vec!["p", &principal.to_hex()],
                vec!["client", "ghostr"],
            ]
        );
    }

    #[test]
    fn an_empty_ghost_note_is_refused() {
        let (ghost, principal) = pubkeys();
        assert!(matches!(
            GhostNoteBuilder::new(ghost, principal).build(1),
            Err(crate::Error::EmptyNote)
        ));
        // Whitespace is empty too — disclosure tags attached to nothing.
        assert!(matches!(
            GhostNoteBuilder::new(ghost, principal)
                .content("   \n\t ")
                .build(1),
            Err(crate::Error::EmptyNote)
        ));
    }

    #[test]
    fn an_undisclosed_note_from_a_relay_is_detected() {
        // The inbound case the builder cannot cover: a third party publishing a
        // ghost note without saying so.
        let (ghost, principal) = pubkeys();
        let bare = UnsignedEvent {
            pubkey: ghost,
            created_at: 1,
            kind: 1,
            tags: Vec::new(),
            content: "trust me, I am him".to_owned(),
        };
        assert!(!has_disclosure(&bare));

        // The marker without a principal is not disclosure: "a ghost" with no
        // "of whom" is nothing a reader can act on.
        let mut marker_only = bare.clone();
        marker_only.tags = vec![DISCLOSURE_TAG.map(str::to_owned).to_vec()];
        assert!(!has_disclosure(&marker_only));

        // A `p` tag that is not a pubkey is decoration.
        let mut junk_principal = marker_only.clone();
        junk_principal
            .tags
            .push(vec!["p".to_owned(), "not-a-pubkey".to_owned()]);
        assert!(!has_disclosure(&junk_principal));

        let mut proper = marker_only;
        proper.tags.push(vec!["p".to_owned(), principal.to_hex()]);
        assert!(has_disclosure(&proper));
    }

    // -----------------------------------------------------------------------
    // The NIP-78 mirror (SPEC Q3)
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn the_mirror_is_the_same_bytes_under_kind_30078() {
        let dir = tempfile::tempdir().expect("tempdir");
        let ks = keystore(dir.path());
        let key = ks.key_ref(Account::Data).expect("key_ref");

        let event = encode(
            &ks,
            key,
            Kind::FootageRecord,
            "2026-08-27",
            1_756_252_800,
            &footage(),
            [42u8; 32],
        )
        .await
        .expect("encode");
        let mirror = mirror_as_nip78(&event).expect("mirror");

        assert_eq!(mirror.kind, 30078);
        // Identical everywhere else. The mirror exists so a reader who cannot
        // resolve 3178x gets the same record, and only the original is anchored
        // — so re-encoding here would let the two drift apart silently.
        assert_eq!(mirror.content, event.content);
        assert_eq!(mirror.tags, event.tags);
        assert_eq!(mirror.pubkey, event.pubkey);
        assert_eq!(mirror.created_at, event.created_at);

        // And it still decodes, which is the whole point of publishing it.
        let mut as_ghostr = mirror.clone();
        as_ghostr.kind = Kind::FootageRecord.as_u16();
        let back: Footage = decode(&ks, key, Kind::FootageRecord, &as_ghostr)
            .await
            .expect("decode");
        assert_eq!(back, footage());
    }

    #[test]
    fn a_ghost_note_has_no_mirror() {
        // Republishing a kind-1 note as application data would carry the
        // disclosure tags into a context where nothing reads them.
        let (ghost, principal) = pubkeys();
        let note = GhostNoteBuilder::new(ghost, principal)
            .content("hello")
            .build(1)
            .expect("build");
        assert!(matches!(
            mirror_as_nip78(&note),
            Err(crate::Error::NotMirrorable { kind: 1 })
        ));
    }

    #[test]
    fn an_event_without_our_d_tag_has_no_mirror() {
        let (ghost, _) = pubkeys();
        let event = UnsignedEvent {
            pubkey: ghost,
            created_at: 1,
            kind: Kind::FootageRecord.as_u16(),
            tags: vec![vec!["d".to_owned(), "someapp/v1/footage/x".to_owned()]],
            content: String::new(),
        };
        assert!(mirror_as_nip78(&event).is_err());
    }
}
