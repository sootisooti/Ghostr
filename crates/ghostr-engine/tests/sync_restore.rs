//! Two machines, one chain: sync, restore, and the rule that stops a fork.
//!
//! This is M3's exit criterion in one file — a vault sealed on one machine,
//! published to relays, and rebuilt on a second machine that starts with
//! nothing but the seed. The second machine must end up with the same history
//! and must **not** be able to extend it.
//!
//! The relay here is a double rather than a websocket server: what is under test
//! is the engine's use of the transport, and `ghostr-nostr` already proves the
//! transport against a real server. The crypto is real throughout — two vaults
//! built from the same mnemonic, actual NIP-44 — because that is the thing a
//! fake would quietly get wrong.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::Path;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use chrono_tz::Tz;
use ghostr_crypto::event::SignedEvent;
use ghostr_crypto::kdf::Argon2Params;
use ghostr_crypto::secret::SecretString;
use ghostr_engine::engine::{DeviceRole, Engine};
use ghostr_engine::ops;
use ghostr_engine::sync::{restore, sync};
use ghostr_nostr::client::{Filter, PublishReport, PublishScope, RelayClient, Subscription};

/// A relay that keeps what it is given.
///
/// Deliberately not filtering on `authors`: a real relay may ignore the filter,
/// and a restore that only works against a well-behaved relay is a restore that
/// has not been tested.
#[derive(Default, Clone)]
struct MemoryRelay {
    stored: Arc<Mutex<Vec<SignedEvent>>>,
}

#[async_trait]
impl RelayClient for MemoryRelay {
    async fn publish(
        &self,
        event: SignedEvent,
        _scope: PublishScope,
    ) -> ghostr_nostr::Result<PublishReport> {
        self.stored.lock().unwrap().push(event);
        Ok(PublishReport {
            accepted: vec!["memory".to_owned()],
            rejected: Vec::new(),
            unreachable: Vec::new(),
        })
    }

    async fn fetch(&self, _filter: &Filter) -> ghostr_nostr::Result<Vec<SignedEvent>> {
        Ok(self.stored.lock().unwrap().clone())
    }

    async fn subscribe(&self, _filter: Filter) -> ghostr_nostr::Result<Box<dyn Subscription>> {
        unreachable!("sync fetches rather than subscribes")
    }
}

const PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon \
                      abandon abandon abandon about";

fn passphrase() -> SecretString {
    SecretString::new("correct horse battery staple".to_owned())
}

fn cheap() -> Argon2Params {
    Argon2Params {
        memory_kib: 8,
        iterations: 1,
        lanes: 1,
    }
}

/// A vault built from the shared mnemonic — same seed, same data key.
fn vault(dir: &Path) -> Engine {
    let (engine, _) = Engine::init(
        dir,
        &passphrase(),
        Tz::UTC,
        Some(SecretString::new(PHRASE.to_owned())),
        None,
        cheap(),
    )
    .expect("init");
    engine
}

fn write_days(dir: &Path, count: u32) {
    std::fs::create_dir_all(dir).unwrap();
    for i in 0..count {
        let day =
            chrono::NaiveDate::from_ymd_opt(2026, 8, 1).unwrap() + chrono::Days::new(i.into());
        std::fs::write(
            dir.join(format!("{day}.md")),
            format!("---\ndate: {day}\n---\nDay {i}. Walked to the river and thought about it.\n"),
        )
        .unwrap();
    }
}

fn seal_days(engine: &Engine, count: u32) {
    for i in 0..count {
        let day =
            chrono::NaiveDate::from_ymd_opt(2026, 8, 1).unwrap() + chrono::Days::new(i.into());
        ops::memoria(engine, day).expect("seal");
    }
}

/// The whole criterion: a clean machine, the seed, and the relays.
#[tokio::test]
async fn a_second_machine_rebuilds_the_chain_from_relays_alone() {
    let tmp = tempfile::tempdir().unwrap();
    let notes = tmp.path().join("notes");
    write_days(&notes, 4);

    // Machine one: seal four days and publish them.
    let first = vault(&tmp.path().join("one"));
    ops::ingest(&first, &notes).expect("ingest");
    seal_days(&first, 4);

    let relay = MemoryRelay::default();
    let report = sync(&first, &relay).await.expect("sync");
    assert_eq!(report.published, 4);
    assert!(report.failed.is_empty());

    // Machine two: nothing but the same seed.
    let second = vault(&tmp.path().join("two"));
    assert_eq!(
        second
            .store()
            .all_footage(second.dek().unwrap())
            .unwrap()
            .len(),
        0
    );

    let restored = restore(&second, &relay).await.expect("restore");
    assert_eq!(restored.recovered, 4);
    assert_eq!(restored.tip, Some(4));
    assert_eq!(restored.rejected, 0);

    // The same history, day for day.
    let original = first.store().all_footage(first.dek().unwrap()).unwrap();
    let rebuilt = second.store().all_footage(second.dek().unwrap()).unwrap();
    assert_eq!(original.len(), rebuilt.len());
    for (a, b) in original.iter().zip(rebuilt.iter()) {
        assert_eq!(a.seq, b.seq);
        assert_eq!(a.date, b.date);
        assert_eq!(a.highlights, b.highlights);
    }
}

/// The restored machine is a replica, and a replica does not seal.
///
/// Two devices advancing the same `seq` forks the chain, and a fork has no
/// resolution rule — there is nothing that says which side is the real history
/// (I3, SPEC §14 Q10).
#[tokio::test]
async fn a_restored_machine_cannot_advance_the_chain() {
    let tmp = tempfile::tempdir().unwrap();
    let notes = tmp.path().join("notes");
    write_days(&notes, 2);

    let first = vault(&tmp.path().join("one"));
    ops::ingest(&first, &notes).expect("ingest");
    seal_days(&first, 2);

    let relay = MemoryRelay::default();
    sync(&first, &relay).await.expect("sync");

    let second = vault(&tmp.path().join("two"));
    assert_eq!(second.device_role().unwrap(), DeviceRole::Sealer);
    restore(&second, &relay).await.expect("restore");
    assert_eq!(second.device_role().unwrap(), DeviceRole::Replica);

    // It has the notes and could compile a day — and still refuses.
    ops::ingest(&second, &notes).expect("a replica may still ingest");
    let next = chrono::NaiveDate::from_ymd_opt(2026, 8, 3).unwrap();
    let err = ops::memoria(&second, next).expect_err("a replica must not seal");
    assert!(format!("{err}").contains("replica"), "{err}");

    // And the machine that has been sealing all along still can.
    let mut later = notes.clone();
    later.push("2026-08-03.md");
    std::fs::write(&later, "---\ndate: 2026-08-03\n---\nStill the sealer.\n").unwrap();
    ops::ingest(&first, &notes).expect("ingest");
    ops::memoria(&first, next).expect("the sealer must still seal");
}

/// Nothing readable reaches a relay, asserted over what sync actually sent.
///
/// `ghostr-nostr` checks this for one hand-built event; this checks it for real
/// footage compiled from real notes, which is where a field could be added
/// later and quietly published in the clear (I1, I9).
#[tokio::test]
async fn no_plaintext_and_no_identity_reaches_a_relay() {
    let tmp = tempfile::tempdir().unwrap();
    let notes = tmp.path().join("notes");
    std::fs::create_dir_all(&notes).unwrap();
    std::fs::write(
        notes.join("2026-08-01.md"),
        "---\ndate: 2026-08-01\n---\nMet Nanthawan at the tea shop about the lease.\n",
    )
    .unwrap();

    let engine = vault(&tmp.path().join("one"));
    ops::ingest(&engine, &notes).expect("ingest");
    seal_days(&engine, 1);

    let relay = MemoryRelay::default();
    sync(&engine, &relay).await.expect("sync");

    let sent = serde_json::to_string(&*relay.stored.lock().unwrap()).unwrap();
    // A deliberately long, distinctive name.
    //
    // A short needle is not a valid absence assertion against ciphertext: NIP-44
    // payloads are base64, and a three-letter string like "Nan" turns up in random
    // base64 roughly once every four hundred blobs. That is exactly how this test
    // failed in CI — a false positive claiming a leak that never happened. Anything
    // asserted absent here must be long enough that a chance hit is impossible,
    // which in practice means a whole word or more.
    for secret in ["Nanthawan", "tea shop", "lease"] {
        assert!(!sent.contains(secret), "`{secret}` reached the relay");
    }

    // And the identity key is nowhere near it: footage is published under the
    // data account, which is what keeps a relay from tying a backup to a person.
    let identity = engine.keystore().identity_pubkey().unwrap();
    assert!(
        !sent.contains(&identity.to_hex()),
        "the identity pubkey reached the relay"
    );
}

/// A relay serving somebody else's events contributes nothing.
#[tokio::test]
async fn a_restore_ignores_events_it_cannot_decrypt() {
    let tmp = tempfile::tempdir().unwrap();
    let notes = tmp.path().join("notes");
    write_days(&notes, 2);

    let first = vault(&tmp.path().join("one"));
    ops::ingest(&first, &notes).expect("ingest");
    seal_days(&first, 2);

    let relay = MemoryRelay::default();
    sync(&first, &relay).await.expect("sync");

    // A stranger's vault publishes to the same relay.
    let stranger_notes = tmp.path().join("stranger-notes");
    write_days(&stranger_notes, 3);
    let (stranger, _) = Engine::init(
        &tmp.path().join("stranger"),
        &passphrase(),
        Tz::UTC,
        Some(SecretString::new(
            "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong".to_owned(),
        )),
        None,
        cheap(),
    )
    .expect("init");
    ops::ingest(&stranger, &stranger_notes).expect("ingest");
    seal_days(&stranger, 3);
    sync(&stranger, &relay).await.expect("sync");

    // Restoring still finds exactly our two days.
    let second = vault(&tmp.path().join("two"));
    let restored = restore(&second, &relay).await.expect("restore");
    assert_eq!(restored.recovered, 2);
    assert!(
        restored.rejected >= 3,
        "the stranger's days were not rejected"
    );
}

/// A relay missing a day in the middle fails the restore rather than half-doing it.
///
/// A chain with a hole is not a chain: seq 1, 2, 4 restored silently would
/// produce a vault whose `verify` fails later, far from the thing that caused
/// it. Refusing here puts the error where the cause is (I3).
#[tokio::test]
async fn a_relay_holding_an_incomplete_chain_is_refused() {
    let tmp = tempfile::tempdir().unwrap();
    let notes = tmp.path().join("notes");
    write_days(&notes, 3);

    let first = vault(&tmp.path().join("one"));
    ops::ingest(&first, &notes).expect("ingest");
    seal_days(&first, 3);

    let relay = MemoryRelay::default();
    sync(&first, &relay).await.expect("sync");
    assert_eq!(relay.stored.lock().unwrap().len(), 3);

    // A relay loses the middle day — expired, pruned, or never accepted.
    {
        let mut stored = relay.stored.lock().unwrap();
        let middle = stored
            .iter()
            .position(|event| {
                event.event.tags.iter().any(|tag| {
                    tag.first().map(String::as_str) == Some("d")
                        && tag.get(1).map(String::as_str) == Some("ghostr/v1/footage/2")
                })
            })
            .expect("the day 2 event");
        stored.remove(middle);
    }

    let second = vault(&tmp.path().join("two"));
    let err = restore(&second, &relay)
        .await
        .expect_err("an incomplete chain must not restore");
    assert!(format!("{err}").contains("incomplete"), "{err}");

    // And nothing was left half-written: the vault is still empty, and still a
    // sealer rather than a replica stranded with a broken history.
    assert_eq!(
        second
            .store()
            .all_footage(second.dek().unwrap())
            .unwrap()
            .len(),
        0
    );
    assert_eq!(second.device_role().unwrap(), DeviceRole::Sealer);
}

/// Anchor receipts are local-only until a human says otherwise.
///
/// A receipt on a relay proves a chain is alive, which is a fact about the
/// person behind it even when nothing in it is readable (SPEC Q5). So it is off
/// in the default config, and turning backup on does not turn it on.
#[test]
fn anchor_receipts_are_not_published_by_default() {
    use ghostr_engine::config::Config;

    let default = Config::default();
    assert!(
        default.enabled_scopes().is_empty(),
        "a fresh vault publishes nothing at all"
    );

    // Enabling backup is not consent to publish liveness.
    let backup_only = Config {
        publish_scopes: vec!["backup".to_owned()],
        ..Config::default()
    };
    let scopes = backup_only.enabled_scopes();
    assert!(scopes.contains(&PublishScope::Backup));
    assert!(
        !scopes.contains(&PublishScope::AnchorReceipts),
        "backup silently enabled anchor receipts"
    );

    // It takes naming the scope.
    let explicit = Config {
        publish_scopes: vec!["anchor_receipts".to_owned()],
        ..Config::default()
    };
    assert!(
        explicit
            .enabled_scopes()
            .contains(&PublishScope::AnchorReceipts)
    );

    // A name from a newer build is ignored rather than refused or, worse,
    // treated as "enable everything".
    let unknown = Config {
        publish_scopes: vec!["backup".to_owned(), "something_new".to_owned()],
        ..Config::default()
    };
    assert_eq!(unknown.enabled_scopes().len(), 1);
}

/// Syncing twice does not publish the same day twice.
#[tokio::test]
async fn a_second_sync_sends_nothing_new() {
    let tmp = tempfile::tempdir().unwrap();
    let notes = tmp.path().join("notes");
    write_days(&notes, 3);

    let engine = vault(&tmp.path().join("one"));
    ops::ingest(&engine, &notes).expect("ingest");
    seal_days(&engine, 3);

    let relay = MemoryRelay::default();
    assert_eq!(sync(&engine, &relay).await.expect("sync").published, 3);

    let again = sync(&engine, &relay).await.expect("sync");
    assert_eq!(again.published, 0);
    assert_eq!(again.already_present, 3);
    assert_eq!(relay.stored.lock().unwrap().len(), 3);
}
