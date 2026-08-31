//! The M1 behaviours that span crates: amendments, threads over many days, and
//! the egress log.
//!
//! No network. The vault, the store, and the chain are real; the model is
//! absent, which is the point — M1's pipeline degrades to the deterministic
//! path rather than refusing to run (CLAUDE.md §4.8).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::Path;

use chrono_tz::Tz;
use ghostr_core::footage::{AmendmentReason, ThreadState};
use ghostr_crypto::kdf::Argon2Params;
use ghostr_crypto::secret::SecretString;
use ghostr_engine::engine::Engine;
use ghostr_engine::ops;

fn passphrase() -> SecretString {
    SecretString::new("correct horse battery staple".to_owned())
}

fn test_params() -> Argon2Params {
    Argon2Params {
        memory_kib: 8,
        iterations: 1,
        lanes: 1,
    }
}

fn init(dir: &Path) -> Engine {
    let (engine, _) =
        Engine::init(dir, &passphrase(), Tz::UTC, None, None, test_params()).expect("init");
    engine
}

fn note(dir: &Path, date: &str, body: &str) {
    note_named(dir, date, date, body);
}

/// A note whose filename and date differ, for the case where two notes belong
/// to the same day.
fn note_named(dir: &Path, name: &str, date: &str, body: &str) {
    std::fs::create_dir_all(dir).unwrap();
    std::fs::write(
        dir.join(format!("{name}.md")),
        format!("---\ndate: {date}\n---\n{body}\n"),
    )
    .unwrap();
}

/// SPEC I2. A memory that turns up after its day sealed does not go back into
/// it — the day's commitment is fixed, and re-deriving it with an extra leaf
/// would break every link after it. It lands in today's footage instead,
/// pointing back at the day it missed.
#[test]
fn a_late_arriving_memory_becomes_an_amendment_not_a_retro_edit() {
    let home = tempfile::tempdir().unwrap();
    let notes = home.path().join("notes");
    let engine = init(&home.path().join("vault"));

    note(&notes, "2026-08-24", "Shipped the parser. A good day.");
    ops::ingest(&engine, &notes).expect("ingest day 1");
    let day1 = ops::memoria(&engine, "2026-08-24".parse().unwrap())
        .expect("seal day 1")
        .footage;
    let sealed_link = day1.commitment.link;
    let sealed_root = day1.commitment.merkle_root;

    // A note *about* day 1, written down on day 2. The front matter dates it to
    // day 1; the filename keeps it a separate file.
    note_named(
        &notes,
        "forgotten",
        "2026-08-24",
        "Also saw the dentist that morning.",
    );
    note(&notes, "2026-08-25", "Fixed the timezone bug.");
    ops::ingest(&engine, &notes).expect("ingest day 2");

    let day2 = ops::memoria(&engine, "2026-08-25".parse().unwrap())
        .expect("seal day 2")
        .footage;

    // The amendment is in today's footage and points backwards.
    assert_eq!(day2.amendments.len(), 1, "one memory arrived late");
    let amendment = &day2.amendments[0];
    assert_eq!(amendment.target_seq, day1.seq);
    assert_eq!(amendment.reason, AmendmentReason::LateArrival);
    assert!(!amendment.memory_ids.is_empty(), "it cites its evidence");

    // Day 1 is untouched: same root, same link, same memory set.
    let reread = engine
        .store()
        .get_footage(engine.dek().unwrap(), day1.seq)
        .expect("read")
        .expect("present");
    assert_eq!(reread.commitment.link, sealed_link);
    assert_eq!(reread.commitment.merkle_root, sealed_root);
    assert_eq!(reread.memory_ids, day1.memory_ids);
    assert!(reread.amendments.is_empty());

    // And the chain still verifies.
    let report = ops::verify(&engine).expect("verify");
    assert!(report.chain_ok && report.roots_ok, "{report:?}");
}

/// A memory that predates the whole chain corrects nothing — there is no sealed
/// day for it to amend — but it is still stored and still counted.
#[test]
fn a_memory_older_than_the_chain_amends_nothing() {
    let home = tempfile::tempdir().unwrap();
    let notes = home.path().join("notes");
    let engine = init(&home.path().join("vault"));

    note(&notes, "2026-08-24", "Day one.");
    ops::ingest(&engine, &notes).expect("ingest");
    ops::memoria(&engine, "2026-08-24".parse().unwrap()).expect("seal day 1");

    note(&notes, "2019-01-01", "Something from years ago.");
    note(&notes, "2026-08-25", "Day two.");
    ops::ingest(&engine, &notes).expect("ingest");

    let day2 = ops::memoria(&engine, "2026-08-25".parse().unwrap())
        .expect("seal day 2")
        .footage;
    assert!(
        day2.amendments.is_empty(),
        "nothing sealed covers 2019, so nothing is corrected"
    );
    // The memory is still in the store.
    assert!(engine.store().memory_count().unwrap() >= 3);
}

/// The M1 exit criterion: a thread opened on one day and resolved several days
/// later shows as a closed loop, having stayed open in between.
#[test]
fn a_thread_opened_early_and_closed_later_is_a_closed_loop() {
    let home = tempfile::tempdir().unwrap();
    let notes = home.path().join("notes");
    let engine = init(&home.path().join("vault"));

    note(
        &notes,
        "2026-08-23",
        "Busy day.\n\n- [ ] call the bank about the transfer\n",
    );
    ops::ingest(&engine, &notes).expect("ingest");
    let opened = ops::memoria(&engine, "2026-08-23".parse().unwrap())
        .expect("seal")
        .footage;
    assert_eq!(opened.open_threads.len(), 1);
    let thread_id = opened.open_threads[0].id;
    assert_eq!(opened.open_threads[0].state, ThreadState::Open);
    assert_eq!(opened.open_threads[0].opened_seq, opened.seq);

    // Days in between: the thread stays open, untouched.
    for date in ["2026-08-24", "2026-08-25"] {
        note(&notes, date, "Nothing much happened.");
        ops::ingest(&engine, &notes).expect("ingest");
        let day = ops::memoria(&engine, date.parse().unwrap())
            .expect("seal")
            .footage;
        assert!(
            day.open_threads.iter().any(|t| t.id == thread_id),
            "{date} should still carry the open thread"
        );
        assert!(day.closed_loops.is_empty());
    }

    // And then it closes.
    note(
        &notes,
        "2026-08-26",
        "Finally did the boring thing.\n\n- [x] call the bank about the transfer\n",
    );
    ops::ingest(&engine, &notes).expect("ingest");
    let closed = ops::memoria(&engine, "2026-08-26".parse().unwrap())
        .expect("seal")
        .footage;

    assert!(
        closed.closed_loops.contains(&thread_id),
        "the loop closes with the id it opened under"
    );
    assert!(
        !closed.open_threads.iter().any(|t| t.id == thread_id),
        "and is no longer open"
    );
    assert_eq!(
        closed.seq - opened.seq,
        3,
        "opened on day 1, closed on day 4"
    );
}

/// Every highlight carries evidence, on every day. The hallucination guard is
/// not a special case for the model path — it is the rule (SPEC §6).
#[test]
fn every_highlight_in_a_sealed_day_cites_a_memory_in_that_day() {
    let home = tempfile::tempdir().unwrap();
    let notes = home.path().join("notes");
    let engine = init(&home.path().join("vault"));

    note(
        &notes,
        "2026-08-24",
        "Shipped the parser.\n\nDinner with @nan about #moving.\n\n- [ ] book a flight\n",
    );
    ops::ingest(&engine, &notes).expect("ingest");
    let day = ops::memoria(&engine, "2026-08-24".parse().unwrap())
        .expect("seal")
        .footage;

    assert!(!day.highlights.is_empty());
    for highlight in &day.highlights {
        assert!(
            !highlight.memory_ids.is_empty(),
            "a highlight cites evidence"
        );
        for memory in &highlight.memory_ids {
            assert!(
                day.memory_ids.contains(memory),
                "and the evidence is in this day's window"
            );
        }
    }
    for person in &day.people {
        assert!(!person.memory_ids.is_empty());
    }
}

/// The whole pipeline, with no model configured and nothing listening on
/// loopback. M1's headline claim is that this works.
#[test]
fn the_pipeline_runs_with_no_model_and_no_network() {
    let home = tempfile::tempdir().unwrap();
    let notes = home.path().join("notes");
    let engine = init(&home.path().join("vault"));

    note(&notes, "2026-08-24", "A day worth remembering. Felt good.");
    ops::ingest(&engine, &notes).expect("ingest");
    let outcome = ops::memoria(&engine, "2026-08-24".parse().unwrap()).expect("seal");

    assert_eq!(outcome.dropped_claims, 0);
    assert!(!outcome.footage.empty);
    let report = ops::verify(&engine).expect("verify");
    assert!(report.chain_ok && report.roots_ok);
    assert_eq!(report.days, 1);
}
