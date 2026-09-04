//! NIP-59 gift wrap: does it actually hide the author?
//!
//! The whole mechanism is one property — a relay holding the wrap must not be
//! able to tell who wrote the rumor — so that is what these test, rather than
//! that the layers round-trip.
//!
//! The recipient's side is reconstructed here from `ghostr-crypto` primitives
//! rather than from a helper, because a helper written alongside the wrapper
//! would agree with its mistakes.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use ghostr_core::identity::{Account, KeyRef};
use ghostr_crypto::event::{SignedEvent, UnsignedEvent};
use ghostr_crypto::kdf::Argon2Params;
use ghostr_crypto::nip44::ConversationKey;
use ghostr_crypto::secret::SecretString;
use ghostr_crypto::signer::GiftWrapEntropy;
use ghostr_crypto::{FileKeystore, Keystore, Signer};

const AUTHOR_PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon \
                             abandon abandon abandon about";
const RECIPIENT_PHRASE: &str = "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong";

const KEY: KeyRef = KeyRef {
    account: Account::Ghost,
};

/// The rumor's own time. Every outer layer must sit at or before this.
const RUMOR_AT: u64 = 1_756_252_800;

fn keystore(dir: &std::path::Path, phrase: &str, name: &str) -> FileKeystore {
    let mnemonic =
        ghostr_crypto::nip06::Mnemonic::parse(SecretString::new(phrase.to_owned())).unwrap();
    let pass = SecretString::new("correct horse battery staple".to_owned());
    let mut ks = FileKeystore::create(
        &dir.join(format!("{name}.json")),
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
    .unwrap();
    ks.unlock(pass).unwrap();
    ks
}

fn entropy() -> GiftWrapEntropy {
    GiftWrapEntropy {
        ephemeral_secret: [0x5A; 32],
        seal_nonce: [0x11; 32],
        wrap_nonce: [0x22; 32],
        // Both in the past relative to the rumor, and independent of each other.
        seal_created_at: RUMOR_AT - 3_600,
        wrap_created_at: RUMOR_AT - 7_200,
    }
}

fn rumor(pubkey: ghostr_core::identity::PublicKey) -> UnsignedEvent {
    UnsignedEvent {
        pubkey,
        created_at: RUMOR_AT,
        kind: 1,
        tags: Vec::new(),
        content: "met Nanthawan at the tea shop about the lease".to_owned(),
    }
}

/// The relay's view: nothing identifying the author survives.
#[tokio::test]
async fn a_wrap_does_not_name_its_author() {
    let dir = tempfile::tempdir().unwrap();
    let author = keystore(dir.path(), AUTHOR_PHRASE, "author");
    let recipient = keystore(dir.path(), RECIPIENT_PHRASE, "recipient");

    let author_pubkey = Signer::public_key(&author, KEY).unwrap();
    let recipient_pubkey = Signer::public_key(&recipient, KEY).unwrap();

    let wrap = author
        .gift_wrap(KEY, &recipient_pubkey, &rumor(author_pubkey), entropy())
        .await
        .expect("gift wrap");

    let seen = serde_json::to_string(&wrap).unwrap();

    // The author's key appears nowhere — not as the event author, not in a tag,
    // not inside the ciphertext.
    assert_ne!(
        wrap.event.pubkey, author_pubkey,
        "the wrap names the author"
    );
    assert!(
        !seen.contains(&author_pubkey.to_hex()),
        "the author's pubkey is in the wrap"
    );
    // Nor is the content readable.
    // Whole words only: a three-letter needle appears in random base64 often
    // enough to fail this test for no reason.
    assert!(!seen.contains("tea shop"));
    assert!(!seen.contains("Nanthawan"));

    assert_eq!(wrap.event.kind, 1059);
    // The recipient tag is the one thing a relay may see: it is how the
    // recipient finds the event at all.
    assert_eq!(
        wrap.event.tags,
        vec![vec!["p".to_owned(), recipient_pubkey.to_hex()]]
    );

    // And it is a real event a relay would accept.
    wrap.verify().expect("the wrap must verify");
}

/// The recipient can actually unwrap it, and finds the real author inside.
#[tokio::test]
async fn the_recipient_recovers_the_rumor_and_the_author() {
    let dir = tempfile::tempdir().unwrap();
    let author = keystore(dir.path(), AUTHOR_PHRASE, "author");
    let recipient = keystore(dir.path(), RECIPIENT_PHRASE, "recipient");

    let author_pubkey = Signer::public_key(&author, KEY).unwrap();
    let recipient_pubkey = Signer::public_key(&recipient, KEY).unwrap();
    let original = rumor(author_pubkey);

    let wrap = author
        .gift_wrap(KEY, &recipient_pubkey, &original, entropy())
        .await
        .expect("gift wrap");

    // Layer 2: decrypt the wrap against the ephemeral key that signed it.
    let seal_json = recipient
        .nip44_decrypt(KEY, &wrap.event.pubkey, &wrap.event.content)
        .await
        .expect("open the wrap");
    let seal: SignedEvent = serde_json::from_slice(&seal_json).expect("a seal");

    assert_eq!(seal.event.kind, 13);
    // NIP-59 is explicit: a kind 13 MUST carry no tags. A tag here would leak
    // exactly what the wrap exists to hide.
    assert!(seal.event.tags.is_empty(), "the seal carries tags");
    // The seal is signed by the *real* author — that is what proves authorship
    // to the recipient and to nobody else.
    assert_eq!(seal.event.pubkey, author_pubkey);
    seal.verify().expect("the seal must verify");

    // Layer 1: decrypt the seal against the author's key.
    let rumor_json = recipient
        .nip44_decrypt(KEY, &author_pubkey, &seal.event.content)
        .await
        .expect("open the seal");
    let recovered: UnsignedEvent = serde_json::from_slice(&rumor_json).expect("a rumor");
    assert_eq!(recovered, original);
}

/// A stranger holding the wrap learns nothing.
#[tokio::test]
async fn someone_who_is_not_the_recipient_cannot_open_it() {
    let dir = tempfile::tempdir().unwrap();
    let author = keystore(dir.path(), AUTHOR_PHRASE, "author");
    let recipient = keystore(dir.path(), RECIPIENT_PHRASE, "recipient");
    let stranger = keystore(dir.path(), AUTHOR_PHRASE, "stranger");

    let author_pubkey = Signer::public_key(&author, KEY).unwrap();
    let recipient_pubkey = Signer::public_key(&recipient, KEY).unwrap();

    let wrap = author
        .gift_wrap(KEY, &recipient_pubkey, &rumor(author_pubkey), entropy())
        .await
        .expect("gift wrap");

    // The stranger holds a different account's key, so ECDH gives a different
    // conversation key and the tag does not verify.
    let stranger_key = KeyRef {
        account: Account::Anchor,
    };
    assert!(
        stranger
            .nip44_decrypt(stranger_key, &wrap.event.pubkey, &wrap.event.content)
            .await
            .is_err()
    );
}

/// The layers must not postdate the rumor.
///
/// NIP-59 puts the canonical time on the rumor and tweaks every outer layer
/// into the past — partly against time analysis, partly because relays refuse
/// events dated in the future.
#[tokio::test]
async fn a_layer_dated_after_the_rumor_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let author = keystore(dir.path(), AUTHOR_PHRASE, "author");
    let recipient = keystore(dir.path(), RECIPIENT_PHRASE, "recipient");
    let author_pubkey = Signer::public_key(&author, KEY).unwrap();
    let recipient_pubkey = Signer::public_key(&recipient, KEY).unwrap();

    for bad in [
        GiftWrapEntropy {
            seal_created_at: RUMOR_AT + 1,
            ..entropy()
        },
        GiftWrapEntropy {
            wrap_created_at: RUMOR_AT + 1,
            ..entropy()
        },
    ] {
        assert!(
            author
                .gift_wrap(KEY, &recipient_pubkey, &rumor(author_pubkey), bad)
                .await
                .is_err()
        );
    }
}

/// One nonce reused across both layers is refused.
#[tokio::test]
async fn a_repeated_nonce_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let author = keystore(dir.path(), AUTHOR_PHRASE, "author");
    let recipient = keystore(dir.path(), RECIPIENT_PHRASE, "recipient");
    let author_pubkey = Signer::public_key(&author, KEY).unwrap();
    let recipient_pubkey = Signer::public_key(&recipient, KEY).unwrap();

    let reused = GiftWrapEntropy {
        wrap_nonce: [0x11; 32],
        ..entropy()
    };
    assert!(
        author
            .gift_wrap(KEY, &recipient_pubkey, &rumor(author_pubkey), reused)
            .await
            .is_err()
    );
}

/// The ephemeral secret never appears in a `Debug` render.
#[test]
fn the_ephemeral_secret_is_not_printable() {
    let printed = format!("{:?}", entropy());
    assert!(!printed.contains("90"), "{printed}");
    assert!(
        !printed.contains("5A") && !printed.contains("5a"),
        "{printed}"
    );
}

/// Two wraps of the same rumor under different ephemeral keys look unrelated.
///
/// If they did not, a relay could group a user's wrapped events even without
/// knowing who wrote them.
#[tokio::test]
async fn two_wraps_of_one_rumor_share_no_visible_identity() {
    let dir = tempfile::tempdir().unwrap();
    let author = keystore(dir.path(), AUTHOR_PHRASE, "author");
    let recipient = keystore(dir.path(), RECIPIENT_PHRASE, "recipient");
    let author_pubkey = Signer::public_key(&author, KEY).unwrap();
    let recipient_pubkey = Signer::public_key(&recipient, KEY).unwrap();

    let first = author
        .gift_wrap(KEY, &recipient_pubkey, &rumor(author_pubkey), entropy())
        .await
        .expect("first");
    let second = author
        .gift_wrap(
            KEY,
            &recipient_pubkey,
            &rumor(author_pubkey),
            GiftWrapEntropy {
                ephemeral_secret: [0x7C; 32],
                wrap_nonce: [0x33; 32],
                ..entropy()
            },
        )
        .await
        .expect("second");

    assert_ne!(first.event.pubkey, second.event.pubkey);
    assert_ne!(first.event.content, second.event.content);
    assert_ne!(first.id, second.id);
}

/// A conversation key derived by hand matches the one the wrap used.
///
/// Guards against the wrap being encrypted to the wrong party — which would
/// still round-trip if both sides shared the same mistake.
#[tokio::test]
async fn the_wrap_is_encrypted_to_the_recipient_and_not_the_author() {
    let dir = tempfile::tempdir().unwrap();
    let author = keystore(dir.path(), AUTHOR_PHRASE, "author");
    let recipient = keystore(dir.path(), RECIPIENT_PHRASE, "recipient");
    let author_pubkey = Signer::public_key(&author, KEY).unwrap();
    let recipient_pubkey = Signer::public_key(&recipient, KEY).unwrap();

    let wrap = author
        .gift_wrap(KEY, &recipient_pubkey, &rumor(author_pubkey), entropy())
        .await
        .expect("gift wrap");

    // Derived independently from the ephemeral secret in `entropy()`.
    let conversation = ConversationKey::derive(&[0x5A; 32], &recipient_pubkey).expect("derive");
    ghostr_crypto::nip44::decrypt(&conversation, &wrap.event.content)
        .expect("the wrap must open under the recipient's conversation key");
}
