//! NIP-46 over relays: the envelope, the filter, and who is allowed to answer.
//!
//! The websocket layer is covered in `relay_transport.rs`; what is specific to
//! this transport is what goes *into* a 24133 event, what it asks the relay for,
//! and which replies it is willing to read. So the relay here is a double that
//! records and replays, and the crypto is real — two keystores, actual NIP-44 —
//! because a fake cipher would agree with whatever this module believes.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use ghostr_core::identity::{Account, KeyRef, PublicKey};
use ghostr_core::time::{Clock, Rng, Timestamp};
use ghostr_crypto::event::{SignedEvent, UnsignedEvent};
use ghostr_crypto::kdf::Argon2Params;
use ghostr_crypto::secret::SecretString;
use ghostr_crypto::{FileKeystore, Keystore, Signer};
use ghostr_nostr::client::{Filter, PublishReport, PublishScope, RelayClient, Subscription};
use ghostr_nostr::nip46::Nip46Transport;
use ghostr_nostr::nip46::relay::RelayNip46Transport;

/// A relay that records what it was asked and returns what it was given.
#[derive(Default)]
struct FakeRelay {
    published: Arc<Mutex<Vec<SignedEvent>>>,
    filters: Arc<Mutex<Vec<Filter>>>,
    /// Replies to hand back on the next `fetch`.
    replies: Arc<Mutex<Vec<SignedEvent>>>,
}

#[async_trait]
impl RelayClient for FakeRelay {
    async fn publish(
        &self,
        event: SignedEvent,
        scope: PublishScope,
    ) -> ghostr_nostr::Result<PublishReport> {
        assert_eq!(
            scope,
            PublishScope::RemoteSigner,
            "a NIP-46 request must publish under its own scope"
        );
        self.published.lock().unwrap().push(event);
        Ok(PublishReport {
            accepted: vec!["fake".to_owned()],
            rejected: Vec::new(),
            unreachable: Vec::new(),
        })
    }

    async fn fetch(&self, filter: &Filter) -> ghostr_nostr::Result<Vec<SignedEvent>> {
        self.filters.lock().unwrap().push(filter.clone());
        Ok(core::mem::take(&mut *self.replies.lock().unwrap()))
    }

    async fn subscribe(&self, _filter: Filter) -> ghostr_nostr::Result<Box<dyn Subscription>> {
        unreachable!("this transport fetches rather than subscribes")
    }
}

struct FixedClock;
impl Clock for FixedClock {
    fn now(&self) -> Timestamp {
        Timestamp::new(1_756_252_800_000, 0)
    }
    fn home_tz(&self) -> chrono_tz::Tz {
        chrono_tz::Tz::UTC
    }
}

struct FixedRng;
impl Rng for FixedRng {
    fn fill(&self, buf: &mut [u8]) {
        buf.fill(0x5A);
    }
}

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

const CLIENT_PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon \
                             abandon abandon abandon about";
const SIGNER_PHRASE: &str = "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong";

const CLIENT_KEY: KeyRef = KeyRef {
    account: Account::Data,
};

/// A transport plus everything a test needs to look behind it.
struct Harness {
    transport: RelayNip46Transport<FakeRelay, FileKeystore>,
    signer_ks: FileKeystore,
    published: Arc<Mutex<Vec<SignedEvent>>>,
    filters: Arc<Mutex<Vec<Filter>>>,
    replies: Arc<Mutex<Vec<SignedEvent>>>,
}

impl Harness {
    /// Queues a reply for the next fetch.
    ///
    /// Takes the event rather than building it, so no lock is held across an
    /// await.
    fn queue(&self, event: SignedEvent) {
        self.replies.lock().unwrap().push(event);
    }
}

/// Builds a transport plus the two keystores behind it.
fn setup(dir: &std::path::Path) -> Harness {
    let client_ks = keystore(dir, CLIENT_PHRASE, "client");
    let signer_ks = keystore(dir, SIGNER_PHRASE, "signer");
    let signer_pubkey = Signer::public_key(&signer_ks, CLIENT_KEY).unwrap();

    let relay = FakeRelay::default();
    let published = Arc::clone(&relay.published);
    let filters = Arc::clone(&relay.filters);
    let replies = Arc::clone(&relay.replies);

    let transport = RelayNip46Transport::new(
        relay,
        client_ks,
        CLIENT_KEY,
        signer_pubkey,
        Box::new(FixedClock),
        Box::new(FixedRng),
    )
    .expect("transport");

    Harness {
        transport,
        signer_ks,
        published,
        filters,
        replies,
    }
}

/// The signer answers: encrypt `body` to the client and publish it as 24133.
async fn reply_from(signer_ks: &FileKeystore, to: &PublicKey, body: &str) -> SignedEvent {
    let content = signer_ks
        .nip44_encrypt(CLIENT_KEY, to, body.as_bytes(), [0x33; 32])
        .await
        .unwrap();
    let event = UnsignedEvent {
        pubkey: Signer::public_key(signer_ks, CLIENT_KEY).unwrap(),
        created_at: 1_756_252_800,
        kind: 24133,
        tags: vec![vec!["p".to_owned(), to.to_hex()]],
        content,
    };
    let sig = signer_ks.sign_event(CLIENT_KEY, &event).await.unwrap();
    SignedEvent {
        id: event.id(),
        event,
        sig,
    }
}

#[tokio::test]
async fn a_request_becomes_an_encrypted_24133_event() {
    let dir = tempfile::tempdir().unwrap();
    let h = setup(dir.path());
    let client_pubkey = *h.transport.client_pubkey();

    h.queue(
        reply_from(
            &h.signer_ks,
            &client_pubkey,
            r#"{"id":"x","result":"pong"}"#,
        )
        .await,
    );

    let answer = h
        .transport
        .round_trip(r#"{"id":"x","method":"ping","params":[]}"#)
        .await
        .expect("round trip");
    assert!(answer.contains("pong"));

    // The envelope: right kind, addressed to the signer, and nothing readable.
    let sent = h.published.lock().unwrap();
    assert_eq!(sent.len(), 1);
    let event = &sent[0];
    assert_eq!(event.event.kind, 24133);
    assert_eq!(
        event.event.tags,
        vec![vec![
            "p".to_owned(),
            Signer::public_key(&h.signer_ks, CLIENT_KEY)
                .unwrap()
                .to_hex()
        ]]
    );
    assert!(
        !event.event.content.contains("ping"),
        "the method name reached the relay in the clear"
    );
    assert!(!event.event.content.contains("method"));

    // And it is a real event: signed by the client key, verifying like any other.
    assert_eq!(event.event.pubkey, client_pubkey);
    event.verify().expect("the envelope must verify");

    // The filter asks only for this signer's replies to this client.
    let asked = h.filters.lock().unwrap();
    let filter = asked.first().expect("a fetch");
    assert_eq!(filter.raw_kinds, vec![24133]);
    assert_eq!(filter.p_tags, vec![client_pubkey]);
    assert_eq!(
        filter.authors,
        vec![Signer::public_key(&h.signer_ks, CLIENT_KEY).unwrap()]
    );
}

/// A stranger's 24133 event, addressed to us, is not an answer.
///
/// Caught by the conversation key rather than by the author check: the content
/// is encrypted to us by *them*, and we only ever decrypt against the signer's
/// key, so it does not open. Worth a test anyway — it is the case an attacker
/// tries first, and "it fails for a different reason than you think" is exactly
/// how a guard rots.
#[tokio::test]
async fn a_reply_from_the_wrong_author_is_ignored() {
    let dir = tempfile::tempdir().unwrap();
    let h = setup(dir.path());
    let client_pubkey = *h.transport.client_pubkey();

    // A third party, correctly signed and correctly addressed to us.
    let impostor = keystore(dir.path(), CLIENT_PHRASE, "impostor");
    let impostor_event = {
        let content = impostor
            .nip44_encrypt(
                CLIENT_KEY,
                &client_pubkey,
                br#"{"id":"x","result":"attacker"}"#,
                [0x44; 32],
            )
            .await
            .unwrap();
        let event = UnsignedEvent {
            pubkey: Signer::public_key(&impostor, CLIENT_KEY).unwrap(),
            created_at: 1_756_252_800,
            kind: 24133,
            tags: vec![vec!["p".to_owned(), client_pubkey.to_hex()]],
            content,
        };
        let sig = impostor.sign_event(CLIENT_KEY, &event).await.unwrap();
        SignedEvent {
            id: event.id(),
            event,
            sig,
        }
    };

    // The impostor first, the real signer second. The reply is built before
    // anything is locked, so no guard is held across an await.
    let genuine = reply_from(
        &h.signer_ks,
        &client_pubkey,
        r#"{"id":"x","result":"pong"}"#,
    )
    .await;
    h.queue(impostor_event);
    h.queue(genuine);

    let answer = h
        .transport
        .round_trip(r#"{"id":"x","method":"ping","params":[]}"#)
        .await
        .expect("round trip");
    assert!(
        !answer.contains("attacker"),
        "an impostor's reply was read as the signer's"
    );
    assert!(answer.contains("pong"));
}

/// A genuine reply, republished by someone else, is ignored.
///
/// This is what the author check actually defends against, and the previous test
/// does not: an attacker who has *seen* one of the signer's replies can copy the
/// ciphertext into an event of their own. It decrypts perfectly — the signer
/// really did encrypt it to us — so the conversation key says nothing. Only the
/// author does.
///
/// Without it, a replayed answer to the current request id passes every other
/// check: `Nip46Signer` compares ids, and a replay carries the id it was
/// answering. Deleting the author re-check makes this test fail.
#[tokio::test]
async fn a_replayed_reply_from_another_author_is_ignored() {
    let dir = tempfile::tempdir().unwrap();
    let h = setup(dir.path());
    let client_pubkey = *h.transport.client_pubkey();

    // A real reply from the signer, whose ciphertext the attacker has copied.
    let genuine = reply_from(
        &h.signer_ks,
        &client_pubkey,
        r#"{"id":"x","result":"stale"}"#,
    )
    .await;

    let attacker = keystore(dir.path(), CLIENT_PHRASE, "replayer");
    let replayed = {
        let event = UnsignedEvent {
            pubkey: Signer::public_key(&attacker, CLIENT_KEY).unwrap(),
            created_at: 1_756_252_800,
            kind: 24133,
            tags: vec![vec!["p".to_owned(), client_pubkey.to_hex()]],
            // The signer's own ciphertext, verbatim.
            content: genuine.event.content.clone(),
        };
        let sig = attacker.sign_event(CLIENT_KEY, &event).await.unwrap();
        SignedEvent {
            id: event.id(),
            event,
            sig,
        }
    };

    let fresh = reply_from(
        &h.signer_ks,
        &client_pubkey,
        r#"{"id":"x","result":"fresh"}"#,
    )
    .await;
    h.queue(replayed);
    h.queue(fresh);

    let answer = h
        .transport
        .round_trip(r#"{"id":"x","method":"ping","params":[]}"#)
        .await
        .expect("round trip");
    assert!(
        !answer.contains("stale"),
        "a replayed reply was read as the signer's answer"
    );
    assert!(answer.contains("fresh"));
}

/// A signer that never answers fails rather than hanging for ever.
#[tokio::test]
async fn a_silent_signer_eventually_fails() {
    let dir = tempfile::tempdir().unwrap();
    let h = setup(dir.path());

    let result = h
        .transport
        .round_trip(r#"{"id":"x","method":"ping","params":[]}"#)
        .await;
    assert!(result.is_err());
    // It really did keep looking rather than giving up on the first empty fetch.
    assert!(h.filters.lock().unwrap().len() > 1);
}
