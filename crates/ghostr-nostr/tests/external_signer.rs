//! Can something that is not a keystore actually be a [`Signer`]?
//!
//! `Signer`'s opening line promises that a NIP-46 remote signer or a hardware
//! device is "a drop-in rather than a rewrite". Until now the only implementor
//! was `FileKeystore`, so the promise was untested — and a seam nobody has
//! crossed is a seam nobody knows the shape of.
//!
//! [`DetachedSigner`] is what an external signer looks like from this side: it
//! holds a key and answers questions about it, and it has no vault, no store, no
//! passphrase and no keystore file. If the codec works through it, then a bunker
//! over a socket or a device on USB is plumbing rather than architecture.
//!
//! # What this found
//!
//! The trait could not be implemented this way at first. `conversation_key`
//! returned a `ConversationKey` — key material — which is the one thing the
//! implementations this seam exists for must never hand out. It has been removed
//! from the trait; this file is what would have caught it.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use async_trait::async_trait;
use ghostr_core::identity::{Account, KeyRef, PublicKey};
use ghostr_crypto::Signer;
use ghostr_crypto::event::{Signature, SignedEvent, UnsignedEvent};
use ghostr_crypto::nip44;
use ghostr_nostr::codec;
use ghostr_nostr::kinds::Kind;
use serde::{Deserialize, Serialize};

/// A signer with no vault behind it.
///
/// Stands in for a bunker or a hardware wallet: it knows one key, performs
/// operations with it, and never returns it. The secret is a plain array here
/// because a test double is not the place a real key lives — the point is the
/// *shape* of what the trait demands, not the storage.
struct DetachedSigner {
    secret: [u8; 32],
    public: PublicKey,
    /// Which account this signer answers for.
    ///
    /// A real bunker holds one key and does not know about NIP-06 accounts, so
    /// it refuses anything else rather than silently signing with the wrong one.
    account: Account,
}

impl DetachedSigner {
    fn new(secret: [u8; 32], account: Account) -> Self {
        let secp = secp256k1::Secp256k1::new();
        let sk = secp256k1::SecretKey::from_byte_array(secret).expect("a valid scalar");
        let (x_only, _) = sk.x_only_public_key(&secp);
        Self {
            secret,
            public: PublicKey::from_bytes(x_only.serialize()),
            account,
        }
    }

    fn check(&self, key: KeyRef) -> ghostr_crypto::Result<()> {
        if key.account == self.account {
            Ok(())
        } else {
            // What a bunker asked for a key it does not hold would say.
            Err(ghostr_crypto::Error::RemoteSigner {
                reason: "this signer holds a different key",
            })
        }
    }
}

#[async_trait]
impl Signer for DetachedSigner {
    fn public_key(&self, key: KeyRef) -> ghostr_crypto::Result<PublicKey> {
        self.check(key)?;
        Ok(self.public)
    }

    async fn sign_event(
        &self,
        key: KeyRef,
        event: &UnsignedEvent,
    ) -> ghostr_crypto::Result<Signature> {
        self.check(key)?;
        if event.pubkey != self.public {
            return Err(ghostr_crypto::Error::KeyMismatch);
        }
        let secp = secp256k1::Secp256k1::new();
        let keypair = secp256k1::Keypair::from_seckey_byte_array(&secp, self.secret)
            .map_err(|_| ghostr_crypto::Error::BadSignature)?;
        // The id from the body, exactly as the trait requires.
        let sig = secp.sign_schnorr_no_aux_rand(event.id().as_bytes(), &keypair);
        Ok(Signature::from_bytes(*sig.as_ref()))
    }

    async fn nip44_encrypt(
        &self,
        key: KeyRef,
        recipient: &PublicKey,
        plaintext: &[u8],
        nonce: [u8; 32],
    ) -> ghostr_crypto::Result<String> {
        self.check(key)?;
        // Derived and used entirely inside the signer. This is the property the
        // trait now allows and previously did not: the conversation key exists
        // for the length of one call and never crosses the boundary.
        let conversation = nip44::ConversationKey::derive(&self.secret, recipient)?;
        nip44::encrypt(&conversation, plaintext, &nonce)
    }

    async fn nip44_decrypt(
        &self,
        key: KeyRef,
        sender: &PublicKey,
        payload: &str,
    ) -> ghostr_crypto::Result<Vec<u8>> {
        self.check(key)?;
        let conversation = nip44::ConversationKey::derive(&self.secret, sender)?;
        nip44::decrypt(&conversation, payload)
    }

    async fn gift_wrap(
        &self,
        _key: KeyRef,
        _recipient: &PublicKey,
        _rumor: &UnsignedEvent,
        _entropy: ghostr_crypto::signer::GiftWrapEntropy,
    ) -> ghostr_crypto::Result<SignedEvent> {
        // A hardware wallet has the same problem a bunker does: the outer wrap
        // needs a signature under a throwaway key, and a device that holds one
        // key does not have one to offer.
        Err(ghostr_crypto::Error::RemoteSigner {
            reason: "this signer cannot sign under a throwaway key",
        })
    }
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct Footage {
    date: String,
    summary: String,
}

fn footage() -> Footage {
    Footage {
        date: "2026-08-31".to_owned(),
        summary: "walked to the river and did not answer the phone".to_owned(),
    }
}

/// The seam, crossed: encode and decode a private kind through a signer that has
/// no vault, no store, and no keystore file.
#[tokio::test]
async fn a_signer_with_no_vault_drives_the_codec() {
    let signer = DetachedSigner::new([0x11; 32], Account::Data);
    let key = KeyRef {
        account: Account::Data,
    };

    let event = codec::encode(
        &signer,
        key,
        Kind::FootageRecord,
        "2026-08-31",
        1_756_252_800,
        &footage(),
        [42u8; 32],
    )
    .await
    .expect("encode");

    // I9 still holds when the signer is external.
    assert!(!event.content.contains("river"));
    assert_eq!(event.kind, 31783);

    let back: Footage = codec::decode(&signer, key, Kind::FootageRecord, &event)
        .await
        .expect("decode");
    assert_eq!(back, footage());
}

/// An event signed by the detached signer verifies like any other.
#[tokio::test]
async fn an_externally_signed_event_verifies() {
    let signer = DetachedSigner::new([0x22; 32], Account::Identity);
    let key = KeyRef {
        account: Account::Identity,
    };

    let event = UnsignedEvent {
        pubkey: signer.public_key(key).expect("pubkey"),
        created_at: 1_756_252_800,
        kind: 31780,
        tags: vec![vec![
            "d".to_owned(),
            "ghostr/v1/manifest/current".to_owned(),
        ]],
        content: String::new(),
    };
    let sig = signer.sign_event(key, &event).await.expect("sign");

    let signed = SignedEvent {
        id: event.id(),
        event,
        sig,
    };
    signed.verify().expect("a relay must accept this");
}

/// A signer asked for a key it does not hold refuses rather than substituting.
///
/// The failure mode a bunker actually has: it holds one key. Silently signing
/// with the wrong one would produce an event that verifies against the wrong
/// person.
#[tokio::test]
async fn a_detached_signer_refuses_a_key_it_does_not_hold() {
    let signer = DetachedSigner::new([0x33; 32], Account::Identity);
    let wrong = KeyRef {
        account: Account::Ghost,
    };

    assert!(signer.public_key(wrong).is_err());
    assert!(
        codec::encode(
            &signer,
            wrong,
            Kind::GhostManifest,
            "current",
            1,
            &footage(),
            [1u8; 32],
        )
        .await
        .is_err()
    );
}

/// The trait is object-safe, and a detached signer satisfies it behind `dyn`.
///
/// `codec::encode` takes `&dyn Signer`, so this is what the call sites actually
/// see. A trait that only worked on a concrete type would be no seam at all.
#[tokio::test]
async fn the_seam_works_through_dyn() {
    let signer: Box<dyn Signer> = Box::new(DetachedSigner::new([0x44; 32], Account::Data));
    let key = KeyRef {
        account: Account::Data,
    };

    let event = codec::encode(
        signer.as_ref(),
        key,
        Kind::QuestSet,
        "2026-08-31",
        1,
        &footage(),
        [7u8; 32],
    )
    .await
    .expect("encode");

    let back: Footage = codec::decode(signer.as_ref(), key, Kind::QuestSet, &event)
        .await
        .expect("decode");
    assert_eq!(back, footage());
}
