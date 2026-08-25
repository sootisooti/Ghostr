//! A month of days, compiled and sealed against a generated corpus.
//!
//! This is the shape M2's fidelity run needs: a corpus with known ground truth,
//! a chain built over it, and assertions that the pipeline *found* what was
//! planted rather than merely producing something. It is worth having now
//! because it exercises the parts of the pipeline that only appear at length —
//! an empty day between two full ones, a thread surviving six seals, a timezone
//! change mid-run.
//!
//! No network, no model. The deterministic path is what is under test.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use chrono::NaiveDate;
use chrono_tz::Tz;
use ghostr_core::time::Timestamp;
use ghostr_crypto::kdf::Argon2Params;
use ghostr_crypto::secret::SecretString;
use ghostr_engine::engine::Engine;
use ghostr_engine::ops;
use ghostr_testkit::adversarial::{InjectionKind, poisoned_corpus};
use ghostr_testkit::{CorpusGenerator, FixedClock, SeededRng, SyntheticCorpus};

const DAYS: u32 = 30;
const START: (i32, u32, u32) = (2026, 1, 5);

fn start_date() -> NaiveDate {
    NaiveDate::from_ymd_opt(START.0, START.1, START.2).expect("valid")
}

fn vault(dir: &std::path::Path) -> Engine {
    let (engine, _) = Engine::init(
        dir,
        &SecretString::new("correct horse battery staple".to_owned()),
        Tz::UTC,
        None,
        Argon2Params {
            memory_kib: 8,
            iterations: 1,
            lanes: 1,
        },
    )
    .expect("init");
    engine
}

fn corpus(generator: &CorpusGenerator) -> SyntheticCorpus {
    let clock = FixedClock::at(Timestamp::new(1_767_000_000_000, 0), Tz::UTC);
    generator.generate(&clock, &SeededRng::from_seed(42))
}

/// Puts a generated corpus straight into the store, bypassing ingest.
///
/// Ingest is markdown-shaped and covered by its own suite; what is under test
/// here is the compile-and-seal loop over a month.
fn load(engine: &Engine, memories: &[ghostr_core::memory::Memory]) {
    let dek = engine.dek().expect("dek");

    // Every source the corpus references, registered before its memories: the
    // memory table has a foreign key to `source`, and injected content
    // deliberately comes from a *different* source than the clean corpus.
    let sources: std::collections::BTreeSet<_> = memories.iter().map(|m| m.source_id).collect();
    for (index, source) in sources.iter().enumerate() {
        engine
            .store()
            .upsert_source(
                dek,
                *source,
                "markdown_vault",
                &format!("{{\"location\":\"/synthetic/{index}\"}}"),
                [u8::try_from(index).unwrap_or(0); 24],
            )
            .expect("source");
    }

    for memory in memories {
        engine
            .store()
            .put_memory(dek, memory, engine.nonce())
            .expect("put");
    }
}

/// Seals every day of the run, in order.
fn seal_all(engine: &Engine) -> Vec<ghostr_core::footage::Footage> {
    (0..DAYS)
        .map(|day| {
            let date = start_date() + chrono::Duration::days(i64::from(day));
            ops::memoria(engine, date).expect("seal").footage
        })
        .collect()
}

/// The headline: thirty days, sealed, verifying.
#[test]
fn a_month_of_synthetic_days_seals_into_a_verifiable_chain() {
    let home = tempfile::tempdir().unwrap();
    let engine = vault(&home.path().join("vault"));
    let corpus = corpus(&CorpusGenerator::new(DAYS).with_empty_days(3));
    load(&engine, &corpus.memories);

    let sealed = seal_all(&engine);
    assert_eq!(sealed.len() as u32, DAYS);

    // Sequence numbers are contiguous from genesis: a gap is indistinguishable
    // from a deletion, so there are none (I3).
    for (index, footage) in sealed.iter().enumerate() {
        assert_eq!(footage.seq, index as u64 + 1);
    }

    let report = ops::verify(&engine).expect("verify");
    assert!(report.chain_ok && report.roots_ok, "{report:?}");
    assert_eq!(report.days, u64::from(DAYS));
}

/// SPEC §3.4. An empty day still seals and still advances `seq` — the path that
/// stays untested until a user takes a weekend off.
#[test]
fn empty_days_seal_and_advance_the_chain() {
    let home = tempfile::tempdir().unwrap();
    let engine = vault(&home.path().join("vault"));
    let corpus = corpus(&CorpusGenerator::new(DAYS).with_empty_days(3));
    load(&engine, &corpus.memories);

    let sealed = seal_all(&engine);
    let empty: Vec<&ghostr_core::footage::Footage> = sealed.iter().filter(|f| f.empty).collect();
    assert_eq!(empty.len(), corpus.ground_truth.empty_days.len());

    for footage in empty {
        assert!(footage.memory_ids.is_empty());
        // An empty day is still a day: it has a root, a link, and a position.
        assert_ne!(footage.commitment.link, footage.commitment.prev_link);
        assert!(footage.commitment.leaf_count >= 1, "the metadata leaf");
    }
    assert!(ops::verify(&engine).expect("verify").chain_ok);
}

/// The planted thread opens on one day and closes six seals later, which is the
/// question threads exist to answer.
#[test]
fn the_planted_thread_survives_the_seals_between_its_ends() {
    let home = tempfile::tempdir().unwrap();
    let engine = vault(&home.path().join("vault"));
    let corpus = corpus(&CorpusGenerator::new(DAYS));
    load(&engine, &corpus.memories);

    let (title, opens, closes) = corpus
        .ground_truth
        .threads
        .first()
        .cloned()
        .expect("a planted thread");
    let closes = closes.expect("this one closes");
    let sealed = seal_all(&engine);

    let opened_on = &sealed[opens as usize];
    let thread = opened_on
        .open_threads
        .iter()
        .find(|t| t.title == title)
        .unwrap_or_else(|| panic!("thread `{title}` not opened on day {opens}"));
    let id = thread.id;

    // Open, untouched, on every day in between.
    for day in (opens + 1)..closes {
        assert!(
            sealed[day as usize].open_threads.iter().any(|t| t.id == id),
            "the thread vanished on day {day}"
        );
        assert!(!sealed[day as usize].closed_loops.contains(&id));
    }

    let closed_on = &sealed[closes as usize];
    assert!(closed_on.closed_loops.contains(&id), "it never closed");
    assert!(!closed_on.open_threads.iter().any(|t| t.id == id));
}

/// The planted cast turns up as person beats, at the frequencies the ground
/// truth claims.
#[test]
fn the_planted_people_are_found_across_the_run() {
    let home = tempfile::tempdir().unwrap();
    let engine = vault(&home.path().join("vault"));
    let corpus = corpus(&CorpusGenerator::new(DAYS));
    load(&engine, &corpus.memories);

    let sealed = seal_all(&engine);
    let mut beats: std::collections::BTreeMap<ghostr_core::ids::EntityId, u32> =
        std::collections::BTreeMap::new();
    for footage in &sealed {
        for person in &footage.people {
            *beats.entry(person.entity).or_default() +=
                u32::try_from(person.memory_ids.len()).unwrap_or(0);
        }
    }

    assert_eq!(
        beats.len(),
        corpus.ground_truth.entities.len(),
        "found {} distinct people, expected {}",
        beats.len(),
        corpus.ground_truth.entities.len()
    );
    let total_planted: u32 = corpus.ground_truth.entities.iter().map(|(_, n)| n).sum();
    let total_found: u32 = beats.values().sum();
    assert_eq!(total_found, total_planted);
}

/// Every claim in every sealed day cites evidence from that day. The
/// hallucination guard, held across a month rather than a single fixture.
#[test]
fn every_claim_in_every_day_cites_evidence_from_that_day() {
    let home = tempfile::tempdir().unwrap();
    let engine = vault(&home.path().join("vault"));
    load(&engine, &corpus(&CorpusGenerator::new(DAYS)).memories);

    for footage in seal_all(&engine) {
        let in_window: std::collections::BTreeSet<_> = footage.memory_ids.iter().copied().collect();
        for highlight in &footage.highlights {
            assert!(!highlight.memory_ids.is_empty(), "seq {}", footage.seq);
            for id in &highlight.memory_ids {
                assert!(in_window.contains(id), "seq {} cites outside", footage.seq);
            }
        }
        for person in &footage.people {
            assert!(!person.memory_ids.is_empty(), "seq {}", footage.seq);
            for id in &person.memory_ids {
                assert!(in_window.contains(id), "seq {} cites outside", footage.seq);
            }
        }
    }
}

/// THREAT_MODEL §T7, end to end. Injections buried in a month of ordinary
/// content are stored and summarised like anything else — and the chain still
/// verifies, because a hostile note is data, not an instruction.
#[test]
fn a_poisoned_corpus_still_seals_into_a_verifiable_chain() {
    let home = tempfile::tempdir().unwrap();
    let engine = vault(&home.path().join("vault"));
    let clean = corpus(&CorpusGenerator::new(DAYS)).memories;
    let clean_count = clean.len();
    let poisoned = poisoned_corpus(clean, InjectionKind::all());
    assert_eq!(poisoned.len(), clean_count + InjectionKind::all().len());
    load(&engine, &poisoned);

    let sealed = seal_all(&engine);
    let report = ops::verify(&engine).expect("verify");
    assert!(report.chain_ok && report.roots_ok, "{report:?}");

    // The injected memories are in the corpus — they were not silently dropped,
    // which would be a different bug — and no highlight anywhere lost its
    // evidence because of them.
    for footage in &sealed {
        for highlight in &footage.highlights {
            assert!(!highlight.memory_ids.is_empty());
        }
    }
}

/// SPEC Q11. A timezone change mid-run is the case cutoff logic is most likely
/// to get wrong, and the chain must stay gapless across it.
#[test]
fn a_timezone_change_midway_leaves_the_chain_gapless() {
    let home = tempfile::tempdir().unwrap();
    let engine = vault(&home.path().join("vault"));
    load(
        &engine,
        &corpus(&CorpusGenerator::new(DAYS).with_timezone_change(15, Tz::Asia__Bangkok)).memories,
    );

    let sealed = seal_all(&engine);
    // Each day's window starts where the previous one ended: no instant belongs
    // to two days, and none belongs to none.
    for pair in sealed.windows(2) {
        assert_eq!(
            pair[0].window.1, pair[1].window.0,
            "gap between seq {} and {}",
            pair[0].seq, pair[1].seq
        );
    }
    assert!(ops::verify(&engine).expect("verify").chain_ok);
}

/// Determinism, at the level that matters — and the boundary between the two
/// halves of a commitment.
///
/// A day's **root** is a function of its content alone, so the same corpus
/// produces the same roots in any vault. Its **link** additionally binds that
/// root to this identity's history, starting from a genesis derived from the
/// keypair — so the same corpus in two vaults produces the same roots and
/// deliberately *different* links. That is what stops one person's chain being
/// mistaken for another's.
#[test]
fn the_same_corpus_gives_the_same_roots_but_identity_bound_links() {
    let commitments = |dir: &std::path::Path| -> Vec<ghostr_core::footage::Commitment> {
        let engine = vault(dir);
        load(&engine, &corpus(&CorpusGenerator::new(10)).memories);
        (0..10)
            .map(|day| {
                let date = start_date() + chrono::Duration::days(i64::from(day));
                ops::memoria(&engine, date)
                    .expect("seal")
                    .footage
                    .commitment
            })
            .collect()
    };

    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    let first = commitments(&a.path().join("v"));
    let second = commitments(&b.path().join("v"));

    let roots = |c: &[ghostr_core::footage::Commitment]| -> Vec<ghostr_core::hash::Hash32> {
        c.iter().map(|x| x.merkle_root).collect()
    };
    assert_eq!(
        roots(&first),
        roots(&second),
        "the same content must hash the same way anywhere"
    );

    assert_ne!(
        first[0].link, second[0].link,
        "two identities must not share a chain"
    );
}
