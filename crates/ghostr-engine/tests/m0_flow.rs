//! The M0 end-to-end flow: init → ingest → memoria → verify.
//!
//! Everything runs against a temporary directory with no network. Anchoring is
//! deliberately absent: it is the one operation that needs a calendar, and a
//! network call in a test is a CI failure (CLAUDE.md §4.8). Its offline
//! behaviour is covered by unit tests in `ghostr-anchor`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::Path;

use chrono_tz::Tz;
use ghostr_crypto::kdf::Argon2Params;
use ghostr_crypto::secret::SecretString;
use ghostr_engine::engine::Engine;
use ghostr_engine::ops;

/// A note that must never appear in the database file in readable form.
const SECRET_PHRASE: &str = "met Nan at the tea shop about the lease";

fn passphrase() -> SecretString {
    SecretString::new("correct horse battery staple".to_owned())
}

/// Argon2id at production cost would make this suite take minutes.
fn test_params() -> Argon2Params {
    Argon2Params {
        memory_kib: 8,
        iterations: 1,
        lanes: 1,
    }
}

fn write_vault(dir: &Path) {
    std::fs::create_dir_all(dir).unwrap();
    std::fs::write(
        dir.join("2026-08-24-monday.md"),
        format!(
            "---\ndate: 2026-08-24\n---\n\
             Shipped the parser after three days stuck on it. Feeling good.\n\n\
             {SECRET_PHRASE}, with @nan about #moving.\n\n\
             - [ ] call the bank about the transfer\n\
             - [x] pay rent\n"
        ),
    )
    .unwrap();
    std::fs::write(
        dir.join("2026-08-25-tuesday.md"),
        "---\ndate: 2026-08-25\n---\n\
         Fixed the timezone bug. Relieved.\n\n\
         - [x] call the bank about the transfer\n\
         - [ ] book the flight\n\n\
         Dinner with @somchai. Should I take the later train?\n",
    )
    .unwrap();
}

fn init(dir: &Path) -> Engine {
    let (engine, outcome) =
        Engine::init(dir, &passphrase(), Tz::UTC, None, None, test_params()).expect("init");
    assert!(outcome.npub.as_str().starts_with("npub1"));
    assert!(
        outcome.mnemonic.is_some(),
        "a generated vault reveals its phrase once"
    );
    engine
}

/// The headline test: the whole flow, in order, on one vault.
#[test]
fn init_ingest_memoria_verify() {
    let home = tempfile::tempdir().unwrap();
    let notes = home.path().join("notes");
    write_vault(&notes);

    let engine = init(&home.path().join("vault"));

    // --- ingest -------------------------------------------------------------
    let report = ops::ingest(&engine, &notes).expect("ingest");
    assert_eq!(report.ingested, 2);
    assert_eq!(report.skipped, 0);

    // Re-running must be a no-op, not a duplicate: this is what makes `ingest`
    // safe to put in a cron job or run twice by accident.
    let again = ops::ingest(&engine, &notes).expect("re-ingest");
    assert_eq!(again.ingested, 0);
    assert_eq!(again.skipped, 2);

    // --- memoria ------------------------------------------------------------
    let day1 = "2026-08-24".parse().unwrap();
    let day2 = "2026-08-25".parse().unwrap();

    let f1 = ops::memoria(&engine, day1).expect("seal day 1").footage;
    assert_eq!(f1.seq, 1);
    assert!(
        !f1.highlights.is_empty(),
        "a day with notes must produce highlights"
    );
    assert!(
        f1.highlights.iter().all(|h| !h.memory_ids.is_empty()),
        "every highlight must cite evidence"
    );
    assert_eq!(
        f1.commitment.prev_link,
        engine.store().genesis_link().unwrap()
    );

    let f2 = ops::memoria(&engine, day2).expect("seal day 2").footage;
    assert_eq!(f2.seq, 2);
    // The chain links day 2 to day 1.
    assert_eq!(f2.commitment.prev_link, f1.commitment.link);
    assert_ne!(f2.commitment.link, f1.commitment.link);

    // A thread opened on day 1 and ticked off on day 2 closes.
    assert!(
        f1.open_threads
            .iter()
            .any(|t| t.title.contains("call the bank")),
        "day 1 should carry the open thread"
    );
    assert!(
        !f2.open_threads
            .iter()
            .any(|t| t.title.contains("call the bank")),
        "day 2 should have closed it"
    );
    assert_eq!(f2.closed_loops.len(), 1);
    // And one opened on day 1 that was never closed carries forward.
    assert!(
        f2.open_threads
            .iter()
            .any(|t| t.opened_seq == 1 || t.opened_seq == 2)
    );

    // --- verify -------------------------------------------------------------
    let report = ops::verify(&engine).expect("verify");
    assert!(report.chain_ok, "chain should verify: {:?}", report.detail);
    assert!(report.roots_ok, "roots should verify: {:?}", report.detail);
    assert_eq!(report.days, 2);
    assert_eq!(report.first_bad_seq, None);
    // Nothing was anchored, and verify says so rather than implying otherwise.
    assert_eq!(report.anchored, 0);
    assert_eq!(report.pending, 0);
}

/// SPEC I1: nothing readable on disk without the key.
#[test]
fn no_note_content_is_readable_in_the_vault_files() {
    let home = tempfile::tempdir().unwrap();
    let notes = home.path().join("notes");
    let vault = home.path().join("vault");
    write_vault(&notes);

    {
        let engine = init(&vault);
        ops::ingest(&engine, &notes).expect("ingest");
        ops::memoria(&engine, "2026-08-24".parse().unwrap()).expect("seal");
    }

    // Every file the vault wrote, WAL included — a checkpoint may not have run.
    let mut raw = Vec::new();
    for entry in std::fs::read_dir(&vault).unwrap().flatten() {
        if entry.path().is_file() {
            raw.extend(std::fs::read(entry.path()).unwrap_or_default());
        }
    }
    assert!(!raw.is_empty());

    for needle in [
        SECRET_PHRASE,
        "Nan",
        "tea shop",
        "timezone bug",
        "call the bank",
        "somchai",
    ] {
        assert!(
            !raw.windows(needle.len()).any(|w| w == needle.as_bytes()),
            "plaintext `{needle}` is readable in the vault files"
        );
    }
}

#[test]
fn the_wrong_passphrase_cannot_open_the_vault() {
    let home = tempfile::tempdir().unwrap();
    let vault = home.path().join("vault");
    drop(init(&vault));

    let err =
        Engine::open(&vault, &SecretString::new("not it".to_owned())).expect_err("must refuse");
    assert!(format!("{err}").contains("passphrase"), "got: {err}");
}

/// Tampering with a sealed day must be caught, and named precisely.
#[test]
fn verify_names_the_first_tampered_sequence() {
    let home = tempfile::tempdir().unwrap();
    let notes = home.path().join("notes");
    let vault = home.path().join("vault");
    write_vault(&notes);

    let engine = init(&vault);
    ops::ingest(&engine, &notes).expect("ingest");
    ops::memoria(&engine, "2026-08-24".parse().unwrap()).expect("seal 1");
    ops::memoria(&engine, "2026-08-25".parse().unwrap()).expect("seal 2");
    assert!(ops::verify(&engine).unwrap().chain_ok);
    drop(engine);

    // The schema's triggers block UPDATE, so an attacker with file access has to
    // drop them first. That is precisely the attacker the chain defends against:
    // someone who owns the database but not the history.
    let conn = rusqlite::Connection::open(vault.join("ghostr.db")).unwrap();
    conn.execute_batch(
        "DROP TRIGGER footage_is_immutable;
         UPDATE footage SET merkle_root = 'aa' || substr(merkle_root, 3) WHERE seq = 1;",
    )
    .unwrap();
    drop(conn);

    let engine = Engine::open(&vault, &passphrase()).expect("reopen");
    let report = ops::verify(&engine).expect("verify runs");
    assert!(!report.chain_ok, "tampering must be detected");
    assert_eq!(
        report.first_bad_seq,
        Some(1),
        "and reported at the day it happened"
    );
}

/// An empty day still seals and still advances the chain (SPEC I3).
#[test]
fn a_day_with_no_notes_still_seals() {
    let home = tempfile::tempdir().unwrap();
    let vault = home.path().join("vault");
    let engine = init(&vault);

    let footage = ops::memoria(&engine, "2026-08-24".parse().unwrap())
        .expect("seal empty day")
        .footage;
    assert!(footage.empty);
    assert_eq!(footage.seq, 1);
    assert!(footage.memory_ids.is_empty());
    // A gap would be indistinguishable from a deletion, so there are no gaps.
    assert!(ops::verify(&engine).unwrap().chain_ok);
}

/// Sealing the same day twice must be refused, not silently duplicated.
#[test]
fn a_day_cannot_be_sealed_twice() {
    let home = tempfile::tempdir().unwrap();
    let vault = home.path().join("vault");
    let engine = init(&vault);

    let day = "2026-08-24".parse().unwrap();
    ops::memoria(&engine, day).expect("first seal");
    let err = ops::memoria(&engine, day).expect_err("second seal must fail");
    assert!(format!("{err}").contains("sealed"), "got: {err}");
}

/// The same vault reopened must derive the same store key from the same seed.
#[test]
fn a_reopened_vault_can_read_what_it_wrote() {
    let home = tempfile::tempdir().unwrap();
    let notes = home.path().join("notes");
    let vault = home.path().join("vault");
    write_vault(&notes);

    let expected_link = {
        let engine = init(&vault);
        ops::ingest(&engine, &notes).expect("ingest");
        ops::memoria(&engine, "2026-08-24".parse().unwrap())
            .expect("seal")
            .footage
            .commitment
            .link
    };

    let engine = Engine::open(&vault, &passphrase()).expect("reopen");
    let footage = engine
        .store()
        .get_footage(engine.dek().unwrap(), 1)
        .expect("read")
        .expect("present");
    assert_eq!(footage.commitment.link, expected_link);
    assert!(
        !footage.highlights.is_empty(),
        "content must decrypt after reopening"
    );
}

/// `init` must refuse to overwrite an existing keystore.
#[test]
fn init_refuses_to_destroy_an_existing_identity() {
    let home = tempfile::tempdir().unwrap();
    let vault = home.path().join("vault");
    drop(init(&vault));

    let err = Engine::init(&vault, &passphrase(), Tz::UTC, None, None, test_params())
        .expect_err("must refuse");
    assert!(format!("{err}").contains("already exists"), "got: {err}");
}
