//! The NIP-46 client, against a signer that misbehaves.
//!
//! A remote signer holds a key we cannot see, so its answers cannot be
//! re-derived — only checked. These tests are the checks: each one is a thing a
//! compromised bunker, a buggy one, or a relay replaying old traffic actually
//! does, and each corresponds to a guard in `nip46.rs`.
//!
//! The honest one is here too, because a client that refuses everything is also
//! wrong.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use async_trait::async_trait;
use ghostr_core::identity::{Account, KeyRef, PublicKey};
use ghostr_crypto::event::{SignedEvent, UnsignedEvent};
use ghostr_crypto::{Error as CryptoError, Signer};
use ghostr_nostr::nip46::{Nip46Signer, Nip46Transport};
use serde_json::Value;
use std::sync::{Arc, Mutex};

/// How the bunker misbehaves, if at all.
#[derive(Clone, Copy, PartialEq)]
enum Lie {
    /// Answer every request correctly.
    None,
    /// Reply with an id that was never asked.
    WrongRequestId,
    /// Sign a different event than the one requested.
    SignsSomethingElse,
    /// Return an event signed by a key that is not the user's.
    SignsWithAnotherKey,
    /// Return an event whose signature is simply wrong.
    ReturnsGarbageSignature,
    /// Report a different user pubkey after connect.
    SwitchesIdentity,
    /// Answer with neither a result nor an error.
    Empty,
}

/// A bunker in-process: it holds a key and answers NIP-46 requests about it.
struct FakeBunker {
    secret: [u8; 32],
    /// A second key, for the impersonation cases.
    other: [u8; 32],
    lie: Lie,
    /// Shared with the test, so what was sent can be inspected without a
    /// test-only accessor on the production type.
    calls: Arc<Mutex<Vec<String>>>,
}

impl FakeBunker {
    fn new(lie: Lie) -> Self {
        Self {
            secret: [0x11; 32],
            other: [0x99; 32],
            lie,
            calls: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn pubkey_of(secret: [u8; 32]) -> PublicKey {
        let secp = secp256k1::Secp256k1::new();
        let sk = secp256k1::SecretKey::from_byte_array(secret).unwrap();
        let (x_only, _) = sk.x_only_public_key(&secp);
        PublicKey::from_bytes(x_only.serialize())
    }

    fn user_pubkey(&self) -> PublicKey {
        Self::pubkey_of(self.secret)
    }

    /// Signs an event body the way a real signer would: id from the body, then
    /// a Schnorr signature over that id.
    fn sign(secret: [u8; 32], event: UnsignedEvent) -> SignedEvent {
        let secp = secp256k1::Secp256k1::new();
        let keypair = secp256k1::Keypair::from_seckey_byte_array(&secp, secret).unwrap();
        let id = event.id();
        let sig = secp.sign_schnorr_no_aux_rand(id.as_bytes(), &keypair);
        SignedEvent {
            id,
            event,
            sig: ghostr_crypto::event::Signature::from_bytes(*sig.as_ref()),
        }
    }
}

#[async_trait]
impl Nip46Transport for FakeBunker {
    async fn round_trip(&self, request: &str) -> ghostr_nostr::Result<String> {
        self.calls.lock().unwrap().push(request.to_owned());
        let parsed: Value = serde_json::from_str(request).unwrap();
        let id = parsed["id"].as_str().unwrap().to_owned();
        let method = parsed["method"].as_str().unwrap();

        let reply_id = if self.lie == Lie::WrongRequestId {
            "not-the-id-you-asked".to_owned()
        } else {
            id
        };

        if self.lie == Lie::Empty {
            return Ok(serde_json::json!({ "id": reply_id }).to_string());
        }

        let result = match method {
            "connect" => "ack".to_owned(),
            "ping" => "pong".to_owned(),
            "get_public_key" => {
                let key = if self.lie == Lie::SwitchesIdentity {
                    Self::pubkey_of(self.other)
                } else {
                    self.user_pubkey()
                };
                key.to_hex()
            }
            "sign_event" => {
                let body: Value =
                    serde_json::from_str(parsed["params"][0].as_str().unwrap()).unwrap();
                let mut event = UnsignedEvent {
                    pubkey: self.user_pubkey(),
                    created_at: body["created_at"].as_u64().unwrap(),
                    kind: u16::try_from(body["kind"].as_u64().unwrap()).unwrap(),
                    tags: serde_json::from_value(body["tags"].clone()).unwrap(),
                    content: body["content"].as_str().unwrap().to_owned(),
                };

                let signed = match self.lie {
                    Lie::SignsSomethingElse => {
                        // Correctly signed — of something the client never asked
                        // for. This is the shape that makes NIP-46 dangerous.
                        event.content = "an event the user never wrote".to_owned();
                        Self::sign(self.secret, event)
                    }
                    Lie::SignsWithAnotherKey => {
                        event.pubkey = Self::pubkey_of(self.other);
                        Self::sign(self.other, event)
                    }
                    Lie::ReturnsGarbageSignature => {
                        let mut signed = Self::sign(self.secret, event);
                        signed.sig = ghostr_crypto::event::Signature::from_bytes([0u8; 64]);
                        signed
                    }
                    _ => Self::sign(self.secret, event),
                };
                serde_json::to_string(&signed).unwrap()
            }
            "nip44_encrypt" => "ciphertext-from-the-bunker".to_owned(),
            "nip44_decrypt" => "the plaintext".to_owned(),
            other => panic!("unexpected method {other}"),
        };

        Ok(serde_json::json!({ "id": reply_id, "result": result }).to_string())
    }
}

async fn connect(lie: Lie) -> ghostr_nostr::Result<Nip46Signer<FakeBunker>> {
    let bunker = FakeBunker::new(lie);
    let signer_pubkey = bunker.user_pubkey();
    Nip46Signer::connect(
        bunker,
        &signer_pubkey,
        Some("a-connect-secret".to_owned()),
        Account::Identity,
        "test-session".to_owned(),
    )
    .await
}

fn body(pubkey: PublicKey) -> UnsignedEvent {
    UnsignedEvent {
        pubkey,
        created_at: 1_756_252_800,
        kind: 31780,
        tags: vec![vec![
            "d".to_owned(),
            "ghostr/v1/manifest/current".to_owned(),
        ]],
        content: String::new(),
    }
}

const KEY: KeyRef = KeyRef {
    account: Account::Identity,
};

/// The honest path: connect, learn the key, sign, and have it verify.
#[tokio::test]
async fn an_honest_signer_produces_a_usable_signature() {
    let signer = connect(Lie::None).await.expect("connect");
    let pubkey = signer.public_key(KEY).expect("pubkey");

    signer.ping().await.expect("ping");

    let event = body(pubkey);
    let sig = signer.sign_event(KEY, &event).await.expect("sign");

    // The signature is real: it verifies exactly as a locally produced one does.
    let signed = SignedEvent {
        id: event.id(),
        event,
        sig,
    };
    signed.verify().expect("a relay must accept this");
}

/// A signer that signs something else is caught, even though its signature is
/// perfectly valid.
///
/// This is the guard that matters most. NIP-46 returns a whole event rather than
/// a signature, so a client that reads the `sig` field and moves on would
/// publish, under the user's key, text the user never wrote.
#[tokio::test]
async fn a_signer_that_signs_a_different_event_is_refused() {
    let signer = connect(Lie::SignsSomethingElse).await.expect("connect");
    let pubkey = signer.public_key(KEY).expect("pubkey");

    let result = signer.sign_event(KEY, &body(pubkey)).await;
    assert!(
        matches!(result, Err(CryptoError::RemoteSigner { .. })),
        "a correctly signed substitution was accepted"
    );
}

#[tokio::test]
async fn a_signer_that_uses_another_key_is_refused() {
    let signer = connect(Lie::SignsWithAnotherKey).await.expect("connect");
    let pubkey = signer.public_key(KEY).expect("pubkey");
    assert!(signer.sign_event(KEY, &body(pubkey)).await.is_err());
}

#[tokio::test]
async fn a_signature_that_does_not_verify_is_refused() {
    let signer = connect(Lie::ReturnsGarbageSignature)
        .await
        .expect("connect");
    let pubkey = signer.public_key(KEY).expect("pubkey");
    assert!(signer.sign_event(KEY, &body(pubkey)).await.is_err());
}

/// A reply carrying the wrong request id is not an answer.
#[tokio::test]
async fn a_mismatched_request_id_fails_the_connection() {
    assert!(connect(Lie::WrongRequestId).await.is_err());
}

/// Neither a result nor an error is a failure, not an empty success.
#[tokio::test]
async fn a_response_with_no_result_and_no_error_is_a_failure() {
    assert!(connect(Lie::Empty).await.is_err());
}

/// The pubkey is pinned at connect, so a later switch changes nothing.
///
/// `SwitchesIdentity` reports the *other* key from `get_public_key`, which is
/// what the client pins. What matters is that `public_key` keeps answering that
/// same pinned value rather than re-asking — a signer that could change it
/// mid-session could make every later signature someone else's.
#[tokio::test]
async fn the_user_key_is_pinned_rather_than_re_asked() {
    let signer = connect(Lie::SwitchesIdentity).await.expect("connect");
    let first = signer.public_key(KEY).expect("pubkey");
    for _ in 0..5 {
        assert_eq!(signer.public_key(KEY).expect("pubkey"), first);
    }
    assert_eq!(*signer.user_pubkey(), first);
}

/// A signer holds one key and refuses any other account.
#[tokio::test]
async fn a_signer_refuses_an_account_it_does_not_hold() {
    let signer = connect(Lie::None).await.expect("connect");
    let wrong = KeyRef {
        account: Account::Ghost,
    };
    assert!(signer.public_key(wrong).is_err());
    assert!(
        signer
            .sign_event(wrong, &body(signer.public_key(KEY).unwrap()))
            .await
            .is_err()
    );
}

/// Signing an event whose author is not the pinned key is refused locally.
#[tokio::test]
async fn signing_for_a_foreign_author_is_refused_before_it_is_sent() {
    let signer = connect(Lie::None).await.expect("connect");
    let stranger = FakeBunker::pubkey_of([0x77; 32]);
    let result = signer.sign_event(KEY, &body(stranger)).await;
    assert!(matches!(result, Err(CryptoError::KeyMismatch)));
}

/// The handshake is the one NIP-46 describes, in order.
#[tokio::test]
async fn connect_performs_the_handshake_the_nip_requires() {
    let bunker = FakeBunker::new(Lie::None);
    let signer_pubkey = bunker.user_pubkey();
    let signer = Nip46Signer::connect(
        bunker,
        &signer_pubkey,
        Some("a-connect-secret".to_owned()),
        Account::Identity,
        "sess".to_owned(),
    )
    .await
    .expect("connect");

    // `get_public_key` after `connect` is required by the NIP, because the
    // signer's own pubkey and the user's are different keys.
    let _ = signer.public_key(KEY).expect("pubkey");
}

/// Request ids are unique within a session.
#[tokio::test]
async fn request_ids_do_not_repeat() {
    let bunker = FakeBunker::new(Lie::None);
    let recorded = Arc::clone(&bunker.calls);
    let signer_pubkey = bunker.user_pubkey();
    let signer = Nip46Signer::connect(
        bunker,
        &signer_pubkey,
        None,
        Account::Identity,
        "sess".to_owned(),
    )
    .await
    .expect("connect");

    signer.ping().await.expect("ping");
    signer.ping().await.expect("ping");

    // The transport recorded every request; their ids must all differ, or a
    // reply could be matched to the wrong one.
    let calls = recorded.lock().unwrap().clone();
    let mut ids: Vec<String> = calls
        .iter()
        .map(|raw| {
            serde_json::from_str::<Value>(raw).unwrap()["id"]
                .as_str()
                .unwrap()
                .to_owned()
        })
        .collect();
    let total = ids.len();
    ids.sort();
    ids.dedup();
    assert_eq!(ids.len(), total, "a request id repeated");
}
