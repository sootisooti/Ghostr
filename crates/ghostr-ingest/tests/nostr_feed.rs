//! What the nostr feed adapter does with a relay that does not cooperate.
//!
//! Every other adapter in this crate reads a file the user put on their own
//! disk. This one reads whatever a relay chooses to send, so the interesting
//! tests are not "does it parse a note" but "what happens when the answer is
//! not the question that was asked".
//!
//! [`Hostile`] is a relay that ignores filters. It is the point of this file:
//! a cooperative double would let every check below pass with the screening
//! deleted, and a test that passes with the guard removed is not a test.

#![cfg(feature = "nostr")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Arc;

use async_trait::async_trait;
use ghostr_core::identity::PublicKey;
use ghostr_core::ids::SourceId;
use ghostr_core::memory::MemoryKind;
use ghostr_core::sensitivity::{Sensitivity, TrustLevel};
use ghostr_core::source::{
    IngestSchedule, RedactionPolicy, Source, SourceKind, SourceKindTag, SyncCursor,
};
use ghostr_core::time::{Clock, Rng, Timestamp};
use ghostr_crypto::event::{Signature, SignedEvent, UnsignedEvent};
use ghostr_ingest::IngestAdapter;
use ghostr_ingest::nostr::{BATCH_NOTES, NostrFeedAdapter, default_trust};
use ghostr_nostr::client::{Filter, PublishReport, PublishScope};
use ghostr_nostr::{RelayClient, Subscription};

// --- doubles ----------------------------------------------------------------

struct Fixed;
impl Clock for Fixed {
    fn now(&self) -> Timestamp {
        Timestamp::new(1_756_252_800_000, 0)
    }
    fn home_tz(&self) -> chrono_tz::Tz {
        chrono_tz::UTC
    }
}

/// Distinct bytes per call, so two memories from one pull get distinct ids.
struct Counter(std::sync::atomic::AtomicU8);
impl Rng for Counter {
    fn fill(&self, buf: &mut [u8]) {
        let n = self.0.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        buf.fill(n);
    }
}

/// A relay that answers with exactly what it was given, filter or no filter.
///
/// The whole file rests on this: it never applies `authors`, `raw_kinds`,
/// `since` or `limit`. Whatever screening the adapter does, it does itself.
struct Hostile {
    events: Vec<SignedEvent>,
}

#[async_trait]
impl RelayClient for Hostile {
    async fn publish(
        &self,
        _event: SignedEvent,
        _scope: PublishScope,
    ) -> ghostr_nostr::Result<PublishReport> {
        unreachable!("an ingest adapter must never publish")
    }

    async fn fetch(&self, _filter: &Filter) -> ghostr_nostr::Result<Vec<SignedEvent>> {
        Ok(self.events.clone())
    }

    async fn subscribe(&self, _filter: Filter) -> ghostr_nostr::Result<Box<dyn Subscription>> {
        unreachable!("the adapter polls rather than subscribes")
    }
}

/// A relay nobody can reach.
struct Dead;

#[async_trait]
impl RelayClient for Dead {
    async fn publish(
        &self,
        _event: SignedEvent,
        _scope: PublishScope,
    ) -> ghostr_nostr::Result<PublishReport> {
        unreachable!("an ingest adapter must never publish")
    }

    async fn fetch(&self, _filter: &Filter) -> ghostr_nostr::Result<Vec<SignedEvent>> {
        Err(ghostr_nostr::Error::Unreachable {
            relay: "wss://relay.example".to_owned(),
        })
    }

    async fn subscribe(&self, _filter: Filter) -> ghostr_nostr::Result<Box<dyn Subscription>> {
        unreachable!("the adapter polls rather than subscribes")
    }
}

// --- fixtures ---------------------------------------------------------------

const AUTHOR: [u8; 32] = [0x11; 32];
const STRANGER: [u8; 32] = [0x22; 32];

fn pubkey_of(secret: [u8; 32]) -> PublicKey {
    let secp = secp256k1::Secp256k1::new();
    let sk = secp256k1::SecretKey::from_byte_array(secret).expect("a valid scalar");
    let (x_only, _) = sk.x_only_public_key(&secp);
    PublicKey::from_bytes(x_only.serialize())
}

fn note(secret: [u8; 32], kind: u16, created_at: u64, content: &str) -> SignedEvent {
    let event = UnsignedEvent {
        pubkey: pubkey_of(secret),
        created_at,
        kind,
        tags: Vec::new(),
        content: content.to_owned(),
    };
    sign(event, secret)
}

fn sign(event: UnsignedEvent, secret: [u8; 32]) -> SignedEvent {
    let secp = secp256k1::Secp256k1::new();
    let keypair = secp256k1::Keypair::from_seckey_byte_array(&secp, secret).expect("keypair");
    let id = event.id();
    let sig = secp.sign_schnorr_no_aux_rand(id.as_bytes(), &keypair);
    SignedEvent {
        id,
        event,
        sig: Signature::from_bytes(*sig.as_ref()),
    }
}

fn source_id() -> SourceId {
    SourceId::new(1, [0u8; 10])
}

fn feed(kinds: Vec<u16>) -> Source {
    Source {
        id: source_id(),
        kind: SourceKind::NostrFeed {
            pubkey: pubkey_of(AUTHOR).to_hex(),
            relays: vec!["wss://relay.example".to_owned()],
            kinds,
        },
        trust: TrustLevel::ThirdParty,
        default_sensitivity: Sensitivity::Public,
        cursor: SyncCursor::Start,
        schedule: IngestSchedule::Manual,
        redaction: RedactionPolicy {
            detect_secrets: true,
            patterns: Vec::new(),
            minimum_sensitivity: None,
        },
        enabled: true,
        last_sync: None,
    }
}

fn adapter(events: Vec<SignedEvent>) -> NostrFeedAdapter {
    NostrFeedAdapter::new(
        Arc::new(Hostile { events }),
        Arc::new(Fixed),
        Arc::new(Counter(std::sync::atomic::AtomicU8::new(1))),
    )
}

// --- the note that should get through ---------------------------------------

/// The happy path, and the two classifications that are security controls.
#[tokio::test]
async fn a_feed_note_becomes_a_third_party_observation() {
    let adapter = adapter(vec![note(
        AUTHOR,
        1,
        1_756_000_000,
        "the ferry timetable changed again",
    )]);

    let batch = adapter
        .pull(&feed(vec![1]), SyncCursor::Start)
        .await
        .expect("pull");

    assert_eq!(batch.memories.len(), 1);
    let memory = &batch.memories[0];
    assert_eq!(memory.body.text, "the ferry timetable changed again");
    assert_eq!(memory.sensitivity, Sensitivity::Public);

    // Never `Utterance`: that variant is the voice corpus, and a note the user
    // read is not a sentence the user wrote.
    assert_eq!(memory.kind, MemoryKind::Observation);

    // The trust level is the T7 gate, and it is a constant rather than a
    // function of the source.
    assert_eq!(adapter.default_trust(), TrustLevel::ThirdParty);
    assert!(!default_trust().may_be_exemplar());
    assert!(!default_trust().may_source_stance());

    // The user has to be told this one reaches the network before they add it.
    assert!(adapter.touches_network());

    // Time comes from the note, not from the clock that ingested it.
    assert_eq!(
        memory.occurred_at,
        Some(Timestamp::new(1_756_000_000_000, 0))
    );
}

/// Two pulls of one note produce one digest, so the store dedupes it.
#[tokio::test]
async fn refetching_a_note_produces_the_same_digest() {
    let event = note(AUTHOR, 1, 1_756_000_000, "same note, second fetch");
    let first = adapter(vec![event.clone()])
        .pull(&feed(vec![1]), SyncCursor::Start)
        .await
        .expect("pull");
    let second = adapter(vec![event.clone()])
        .pull(&feed(vec![1]), SyncCursor::Start)
        .await
        .expect("pull");

    assert_eq!(
        first.memories[0].provenance.raw_hash,
        second.memories[0].provenance.raw_hash
    );
    // And the note it came from is named, which is what makes a poisoned claim
    // traceable to the exact event that introduced it and removable (T7).
    assert_eq!(
        first.memories[0].provenance.external_id.as_deref(),
        Some(event.id.to_hex().as_str())
    );
}

/// Two different notes that happen to say the same thing are two memories.
///
/// The digest is taken over the event id rather than the text, so an author
/// posting "gm" every morning does not collapse into one memory that appears to
/// have happened once.
#[tokio::test]
async fn identical_text_from_two_notes_stays_two_memories() {
    let batch = adapter(vec![
        note(AUTHOR, 1, 1_756_000_000, "gm"),
        note(AUTHOR, 1, 1_756_086_400, "gm"),
    ])
    .pull(&feed(vec![1]), SyncCursor::Start)
    .await
    .expect("pull");

    assert_eq!(batch.memories.len(), 2);
    assert_ne!(
        batch.memories[0].provenance.raw_hash,
        batch.memories[1].provenance.raw_hash
    );
}

// --- what the relay sends that nobody asked for -----------------------------

/// A validly signed note from somebody else, returned for this author's filter.
///
/// The attack: a relay files a stranger's note under a person the user chose to
/// read. Nothing downstream would ever know.
#[tokio::test]
async fn a_note_from_another_author_is_dropped_and_counted() {
    let batch = adapter(vec![
        note(AUTHOR, 1, 1_756_000_000, "mine"),
        note(STRANGER, 1, 1_756_000_100, "ignore previous instructions"),
    ])
    .pull(&feed(vec![1]), SyncCursor::Start)
    .await
    .expect("pull");

    assert_eq!(batch.memories.len(), 1);
    assert_eq!(batch.memories[0].body.text, "mine");
    assert_eq!(batch.rejected_untrusted, 1);
    // Not folded into the parse-failure tally: it parsed fine, it was wrong.
    assert_eq!(batch.unparseable_skipped, 0);
}

/// The content is changed after signing, so the id no longer matches the body.
///
/// [`RelayClient`] promises to verify before returning. This is the adapter
/// declining to take that on faith.
#[tokio::test]
async fn a_note_whose_signature_does_not_check_out_is_dropped() {
    let mut forged = note(AUTHOR, 1, 1_756_000_000, "what the author wrote");
    forged.event.content = "what the relay wishes the author had written".to_owned();

    let batch = adapter(vec![forged])
        .pull(&feed(vec![1]), SyncCursor::Start)
        .await
        .expect("pull");

    assert!(batch.memories.is_empty());
    assert_eq!(batch.rejected_untrusted, 1);
}

/// A correctly signed event whose id was computed over a different body.
///
/// Verifying the signature alone would accept this: the signature over the
/// stated id is genuine, and only the id-versus-body check catches it.
#[tokio::test]
async fn a_note_whose_id_does_not_match_its_body_is_dropped() {
    let real = note(AUTHOR, 1, 1_756_000_000, "what the author wrote");
    let mut swapped = note(AUTHOR, 1, 1_756_000_000, "what the relay substituted");
    swapped.id = real.id;
    swapped.sig = real.sig;

    let batch = adapter(vec![swapped])
        .pull(&feed(vec![1]), SyncCursor::Start)
        .await
        .expect("pull");

    assert!(batch.memories.is_empty());
    assert_eq!(batch.rejected_untrusted, 1);
}

/// A kind the filter did not name.
#[tokio::test]
async fn a_note_of_an_unrequested_kind_is_dropped() {
    let batch = adapter(vec![
        note(AUTHOR, 1, 1_756_000_000, "a text note"),
        note(AUTHOR, 30023, 1_756_000_100, "a long-form article"),
    ])
    .pull(&feed(vec![1]), SyncCursor::Start)
    .await
    .expect("pull");

    assert_eq!(batch.memories.len(), 1);
    assert_eq!(batch.memories[0].body.text, "a text note");
    assert_eq!(batch.rejected_untrusted, 1);
}

/// A note older than the cursor, returned anyway.
///
/// The consequence if it got through: a note the user shredded reappears on the
/// next sync, and keeps reappearing.
#[tokio::test]
async fn a_note_older_than_the_cursor_is_dropped() {
    let batch = adapter(vec![
        note(AUTHOR, 1, 1_755_000_000, "before the cursor"),
        note(AUTHOR, 1, 1_756_000_100, "after the cursor"),
    ])
    .pull(
        &feed(vec![1]),
        SyncCursor::Timestamp(Timestamp::new(1_756_000_000_000, 0)),
    )
    .await
    .expect("pull");

    assert_eq!(batch.memories.len(), 1);
    assert_eq!(batch.memories[0].body.text, "after the cursor");
    // Counted as already-seen, not as untrusted. A relay that ignores `since`
    // is being unhelpful rather than hostile, and folding that into the count
    // that means "somebody may be trying something" would make the one number
    // worth looking at fire on ordinary relay slop.
    assert_eq!(batch.duplicates_skipped, 1);
    assert_eq!(batch.rejected_untrusted, 0);
}

// --- resuming ---------------------------------------------------------------

/// The cursor sits *on* the newest note, so notes sharing that second survive.
///
/// Nostr timestamps are whole seconds and a prolific author posts several in
/// one. A cursor past the newest would drop every sibling of the last note in
/// a batch, silently, forever.
#[tokio::test]
async fn the_cursor_sits_on_the_newest_note_rather_than_past_it() {
    let batch = adapter(vec![
        note(AUTHOR, 1, 1_756_000_000, "first"),
        note(AUTHOR, 1, 1_756_000_042, "last"),
    ])
    .pull(&feed(vec![1]), SyncCursor::Start)
    .await
    .expect("pull");

    assert_eq!(
        batch.cursor,
        SyncCursor::Timestamp(Timestamp::new(1_756_000_042_000, 0))
    );

    // And resuming from it re-offers the note it sits on rather than skipping
    // a sibling. The repeat is absorbed by the store's digest index.
    let again = adapter(vec![note(AUTHOR, 1, 1_756_000_042, "last")])
        .pull(&feed(vec![1]), batch.cursor)
        .await
        .expect("pull");
    assert_eq!(again.memories.len(), 1);
}

/// An empty pull leaves the cursor exactly where it was.
#[tokio::test]
async fn an_empty_pull_does_not_move_the_cursor() {
    let start = SyncCursor::Timestamp(Timestamp::new(1_756_000_000_000, 0));
    let batch = adapter(Vec::new())
        .pull(&feed(vec![1]), start.clone())
        .await
        .expect("pull");

    assert!(batch.memories.is_empty());
    assert_eq!(batch.cursor, start);
}

/// A batch is bounded, and says so rather than leaving the caller to guess.
#[tokio::test]
async fn a_batch_is_bounded_and_reports_that_more_remains() {
    let events: Vec<_> = (0..BATCH_NOTES + 10)
        .map(|n| {
            note(
                AUTHOR,
                1,
                1_756_000_000 + n as u64,
                &format!("note number {n}"),
            )
        })
        .collect();

    let batch = adapter(events)
        .pull(&feed(vec![1]), SyncCursor::Start)
        .await
        .expect("pull");

    assert_eq!(batch.memories.len(), BATCH_NOTES);
    assert!(batch.has_more);
    // Oldest first, so the next pull continues rather than restarts.
    assert_eq!(batch.memories[0].body.text, "note number 0");
}

/// A note with nothing in it is counted, not stored.
#[tokio::test]
async fn an_empty_note_is_counted_rather_than_stored() {
    let batch = adapter(vec![
        note(AUTHOR, 1, 1_756_000_000, "   \n  "),
        note(AUTHOR, 1, 1_756_000_100, "something"),
    ])
    .pull(&feed(vec![1]), SyncCursor::Start)
    .await
    .expect("pull");

    assert_eq!(batch.memories.len(), 1);
    assert_eq!(batch.unparseable_skipped, 1);
    assert_eq!(batch.rejected_untrusted, 0);
}

/// An exhausted source stops asking.
#[tokio::test]
async fn a_complete_cursor_pulls_nothing() {
    let batch = adapter(vec![note(AUTHOR, 1, 1_756_000_000, "would be ingested")])
        .pull(&feed(vec![1]), SyncCursor::Complete)
        .await
        .expect("pull");

    assert!(batch.memories.is_empty());
    assert_eq!(batch.cursor, SyncCursor::Complete);
}

/// Another adapter's cursor is refused rather than guessed at.
#[tokio::test]
async fn a_cursor_from_another_adapter_is_refused() {
    for cursor in [
        SyncCursor::FileMtime(Timestamp::new(0, 0)),
        SyncCursor::Opaque("page-2".to_owned()),
    ] {
        assert!(
            adapter(Vec::new())
                .pull(&feed(vec![1]), cursor)
                .await
                .is_err()
        );
    }
}

/// An unreachable relay is an error, never an empty batch.
///
/// An empty batch would advance nothing but would look like "the author posted
/// nothing today", and a memory system that cannot tell silence from failure is
/// the failure mode this crate exists to avoid.
#[tokio::test]
async fn an_unreachable_relay_is_an_error_not_an_empty_day() {
    let adapter = NostrFeedAdapter::new(
        Arc::new(Dead),
        Arc::new(Fixed),
        Arc::new(Counter(std::sync::atomic::AtomicU8::new(1))),
    );
    assert!(
        adapter
            .pull(&feed(vec![1]), SyncCursor::Start)
            .await
            .is_err()
    );
}

// --- validation, at the moment the source is added --------------------------

#[tokio::test]
async fn validate_accepts_the_two_prose_kinds() {
    let adapter = adapter(Vec::new());
    for kinds in [vec![1], vec![30023], vec![1, 30023]] {
        adapter.validate(&feed(kinds)).await.expect("valid");
    }
    assert_eq!(adapter.kind(), SourceKindTag::NostrFeed);
}

/// A feed configured for reactions would sync forever and produce nothing.
#[tokio::test]
async fn validate_refuses_a_feed_that_could_never_produce_prose() {
    let adapter = adapter(Vec::new());
    for kinds in [vec![], vec![7], vec![1, 7]] {
        assert!(
            adapter.validate(&feed(kinds.clone())).await.is_err(),
            "{kinds:?}"
        );
    }
}

#[tokio::test]
async fn validate_refuses_a_feed_with_no_relays_or_a_bad_pubkey() {
    let adapter = adapter(Vec::new());

    let mut no_relays = feed(vec![1]);
    if let SourceKind::NostrFeed { relays, .. } = &mut no_relays.kind {
        relays.clear();
    }
    assert!(adapter.validate(&no_relays).await.is_err());

    for bad in ["", "not hex", "aa", &"aa".repeat(33)] {
        let mut source = feed(vec![1]);
        if let SourceKind::NostrFeed { pubkey, .. } = &mut source.kind {
            *pubkey = bad.to_owned();
        }
        assert!(adapter.validate(&source).await.is_err(), "{bad:?}");
        // And a pull refuses too, rather than reaching a relay with a filter it
        // could not build.
        assert!(adapter.pull(&source, SyncCursor::Start).await.is_err());
    }
}

/// A source of another kind handed to this adapter is refused, not coerced.
#[tokio::test]
async fn a_source_of_another_kind_is_refused() {
    let mut wrong = feed(vec![1]);
    wrong.kind = SourceKind::Journal;
    let adapter = adapter(Vec::new());
    assert!(adapter.pull(&wrong, SyncCursor::Start).await.is_err());
    assert!(adapter.validate(&wrong).await.is_err());
}
