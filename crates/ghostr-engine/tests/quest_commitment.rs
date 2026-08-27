//! Quests in the day's Merkle tree, and the migration that keeps old chains valid.
//!
//! SPEC §4.3 says a quest's answer commitment is anchored, and §7.3 puts
//! `quest_leaf` in `root_n`. Until now neither was true: the commitment was
//! immutable because a database trigger said so, which is a promise about a
//! file rather than about Bitcoin.
//!
//! The awkward half is that adding a leaf kind changes every root that has one,
//! and a root already anchored cannot be recomputed. So a day is verified under
//! the rules it was *sealed* under, and these tests are mostly about that.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::Path;

use chrono::NaiveDate;
use chrono_tz::Tz;
use ghostr_core::footage::CommitmentVersion;
use ghostr_core::quest::Verdict;
use ghostr_core::sensitivity::{Sensitivity, TrustLevel};
use ghostr_core::time::Timestamp;
use ghostr_crypto::kdf::Argon2Params;
use ghostr_crypto::secret::SecretString;
use ghostr_engine::engine::Engine;
use ghostr_engine::ops;
use ghostr_testkit::{CorpusGenerator, FixedClock, SeededRng};

const DAYS: u32 = 30;
const EPOCH_MILLIS: i64 = 1_767_571_200_000;

fn start_date() -> NaiveDate {
    NaiveDate::from_ymd_opt(2026, 1, 5).expect("valid")
}

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

/// A vault with a corpus, sealed days, and an adopted persona.
fn ready(dir: &Path) -> (Engine, FixedClock) {
    Engine::init(dir, &passphrase(), Tz::UTC, None, cheap()).expect("init");
    let clock = FixedClock::at(Timestamp::new(EPOCH_MILLIS, 0), Tz::UTC);
    let engine = Engine::open_with(
        dir,
        &passphrase(),
        Some(Box::new(clock.clone())),
        Some(Box::new(SeededRng::from_seed(7))),
    )
    .expect("open");

    let fixed = FixedClock::at(Timestamp::new(1_767_000_000_000, 0), Tz::UTC);
    let corpus = CorpusGenerator::new(DAYS).generate(&fixed, &SeededRng::from_seed(42));
    let dek = engine.dek().expect("dek");
    let sources: std::collections::BTreeSet<_> =
        corpus.memories.iter().map(|m| m.source_id).collect();
    for (index, source) in sources.iter().enumerate() {
        engine
            .store()
            .upsert_source_with(
                dek,
                &ghostr_store::sqlite::NewSourceRow {
                    id: *source,
                    kind_tag: "markdown_vault",
                    config: "{\"location\":\"/synthetic\"}",
                    trust: TrustLevel::FirstParty,
                    sensitivity: Sensitivity::Private,
                },
                [u8::try_from(index).unwrap_or(0); 24],
            )
            .expect("source");
    }
    for memory in &corpus.memories {
        engine
            .store()
            .put_memory(dek, memory, engine.nonce())
            .expect("put");
    }
    (engine, clock)
}

/// Seals `days`, issuing and answering quests along the way.
fn run(engine: &Engine, clock: &FixedClock, days: u32) {
    let persona_at = 3;
    for day in 0..days {
        let date = start_date() + chrono::Duration::days(i64::from(day));

        if day == persona_at {
            let candidate = ops::propose_persona(engine).expect("propose");
            ops::adopt_persona(engine, &candidate).expect("adopt");
        }
        if day >= persona_at {
            ops::issue_quests(engine, date).expect("issue");
            for quest in ops::open_quests(engine, 100).expect("open") {
                clock.advance(30);
                ops::answer_quest(engine, quest.id, Verdict::Confirm).expect("answer");
            }
        }
        ops::memoria(engine, date).expect("seal");
        clock.advance(86_400 - 3_600);
    }
}

/// The headline: a day that issued quests commits to them, and the chain that
/// results verifies.
#[test]
fn a_days_quests_are_in_its_root_and_the_chain_verifies() {
    let home = tempfile::tempdir().unwrap();
    let (engine, clock) = ready(&home.path().join("vault"));
    run(&engine, &clock, 10);

    let report = ops::verify(&engine).expect("verify");
    assert!(report.chain_ok && report.roots_ok, "{report:?}");

    let dek = engine.dek().expect("dek");
    let all = engine.store().all_footage(dek).expect("footage");
    let with_quests: Vec<_> = all
        .iter()
        .filter(|f| {
            !engine
                .store()
                .quests_committed_at(dek, f.seq)
                .expect("quests")
                .is_empty()
        })
        .collect();
    assert!(!with_quests.is_empty(), "no day issued quests");

    // Leaves beyond the metadata leaf and the day's memories: the quests, and
    // the verdicts given that day.
    for f in with_quests {
        let memories = engine.store().footage_leaves(f.seq).expect("leaves").len();
        assert!(
            f.commitment.leaf_count as usize > memories + 1,
            "seq {} committed to nothing beyond its memories",
            f.seq
        );
        assert_eq!(f.commitment.version, CommitmentVersion::WithQuests);
    }
}

/// I6, now against the chain rather than against a database trigger. Removing a
/// quest after its day sealed must break the root.
///
/// Reaches past the API with raw SQL, exactly as someone holding the vault file
/// and the passphrase could. That is the threat: the database's own triggers are
/// a promise about a file, and this is what makes it a promise about Bitcoin.
#[test]
fn removing_a_sealed_days_quest_breaks_its_root() {
    let home = tempfile::tempdir().unwrap();
    let dir = home.path().join("vault");
    let day_seq;
    {
        let (engine, clock) = ready(&dir);
        run(&engine, &clock, 10);
        assert!(ops::verify(&engine).expect("verify").roots_ok);

        let dek = engine.dek().expect("dek");
        let day = engine
            .store()
            .all_footage(dek)
            .expect("footage")
            .into_iter()
            .find(|f| {
                !engine
                    .store()
                    .quests_committed_at(dek, f.seq)
                    .expect("q")
                    .is_empty()
            })
            .expect("a day with quests");
        day_seq = day.seq;

        let victim = engine
            .store()
            .quests_committed_at(dek, day.seq)
            .expect("quests")
            .remove(0);
        let db = rusqlite::Connection::open(dir.join(ghostr_store::DB_FILENAME)).expect("open db");
        db.execute("DELETE FROM quest WHERE id = ?1", [victim.id.to_string()])
            .expect("delete");
    }

    let engine = Engine::open(&dir, &passphrase()).expect("reopen");
    let report = ops::verify(&engine).expect("verify");
    assert!(
        !report.roots_ok,
        "a quest removed after sealing left the root intact: {report:?}"
    );
    assert_eq!(report.first_bad_seq, Some(day_seq));
}

/// A verdict belongs to the day it was *given*. A quest issued on one day and
/// answered on the next cannot go into the first day's tree, because that day
/// has sealed and a sealed footage is immutable (I2).
#[test]
fn a_verdict_is_committed_to_the_day_it_was_given() {
    let home = tempfile::tempdir().unwrap();
    let (engine, clock) = ready(&home.path().join("vault"));

    // Three days of corpus, then a persona, then a quest left unanswered
    // overnight.
    for day in 0..4 {
        ops::memoria(&engine, start_date() + chrono::Duration::days(day)).expect("seal");
        clock.advance(86_400);
    }
    let candidate = ops::propose_persona(&engine).expect("propose");
    ops::adopt_persona(&engine, &candidate).expect("adopt");

    let asked_on = start_date() + chrono::Duration::days(4);
    ops::issue_quests(&engine, asked_on).expect("issue");
    let quest = ops::open_quests(&engine, 1).expect("open").remove(0);
    ops::memoria(&engine, asked_on).expect("seal the asking day");

    // Next day: answer it, then seal.
    clock.advance(86_400);
    let answered_on = asked_on.succ_opt().expect("next");
    ops::answer_quest(&engine, quest.id, Verdict::Confirm).expect("answer");
    ops::memoria(&engine, answered_on).expect("seal the answering day");

    let report = ops::verify(&engine).expect("verify");
    assert!(
        report.chain_ok && report.roots_ok,
        "a verdict landing after its day sealed broke the chain: {report:?}"
    );

    let dek = engine.dek().expect("dek");
    let all = engine.store().all_footage(dek).expect("footage");
    let asking = all.iter().find(|f| f.date == asked_on).expect("asking day");
    let answering = all
        .iter()
        .find(|f| f.date == answered_on)
        .expect("answering day");

    // The answering day has a leaf the asking day does not: the verdict.
    let leaves_of = |f: &ghostr_core::footage::Footage| {
        f.commitment.leaf_count as usize
            - 1
            - engine.store().footage_leaves(f.seq).expect("leaves").len()
    };
    assert!(leaves_of(asking) >= 1, "the asking day committed its quest");
    assert!(
        leaves_of(answering) >= 1,
        "the answering day committed no verdict"
    );
}
