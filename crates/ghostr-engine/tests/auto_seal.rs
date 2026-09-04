//! Sealing days that are over, without anyone typing a command.
//!
//! The daily loop only works if the days actually close, and a person who has
//! to remember a command every evening will not. What is under test is the
//! decision of *which* days are due — the thread in `serve` that calls it is
//! four lines and a sleep.
//!
//! A fixed clock throughout: the grace window is measured in hours, and a test
//! that waited them out would take a morning.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::Path;

use chrono::NaiveDate;
use chrono_tz::Tz;
use ghostr_core::time::Timestamp;
use ghostr_crypto::kdf::Argon2Params;
use ghostr_crypto::secret::SecretString;
use ghostr_engine::engine::{DeviceRole, Engine};
use ghostr_engine::ops;
use ghostr_testkit::time::{FixedClock, SeededRng};

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

/// UTC millis for a local wall-clock moment in `tz`.
fn at(date: NaiveDate, hour: u32, tz: Tz) -> Timestamp {
    use chrono::TimeZone as _;
    let local = date.and_hms_opt(hour, 0, 0).unwrap();
    Timestamp::new(
        tz.from_local_datetime(&local)
            .earliest()
            .unwrap()
            .timestamp_millis(),
        0,
    )
}

const TZ: Tz = Tz::UTC;

/// A vault whose clock reads `now`.
fn vault_at(dir: &Path, now: Timestamp) -> Engine {
    if !dir.join("keystore.json").exists() {
        let (engine, _) = Engine::init(dir, &passphrase(), TZ, None, None, cheap()).expect("init");
        // `init` stamps genesis with the wall clock, and the whole point of a
        // fixed clock here is that these tests do not live in the present. The
        // genesis date is backdated so the vault existed for the days under
        // test — otherwise every day is refused as predating the chain, which
        // is correct behaviour and useless for testing anything else.
        engine
            .store()
            .set_meta(
                ghostr_store::schema::meta_key::CREATED_AT,
                &at(day(1), 0, TZ).utc_millis().to_string(),
            )
            .expect("backdate genesis");
        drop(engine);
    }
    Engine::open_with(
        dir,
        &passphrase(),
        Some(Box::new(FixedClock::at(now, TZ))),
        Some(Box::new(SeededRng::from_seed(7))),
    )
    .expect("open")
}

fn write_note(dir: &Path, date: NaiveDate) {
    std::fs::create_dir_all(dir).unwrap();
    std::fs::write(
        dir.join(format!("{date}.md")),
        format!("---\ndate: {date}\n---\nSomething happened on {date}.\n"),
    )
    .unwrap();
}

fn day(n: u32) -> NaiveDate {
    NaiveDate::from_ymd_opt(2026, 8, n).unwrap()
}

/// Three days missed while the machine was off, sealed oldest first.
///
/// Order is not cosmetic: `seq` is assigned as `tip + 1`, so sealing the newest
/// day first is refused by the store — and would be the wrong history anyway.
#[test]
fn a_weekend_away_is_filled_in_oldest_first() {
    let tmp = tempfile::tempdir().unwrap();
    let notes = tmp.path().join("notes");
    for n in 1..=3 {
        write_note(&notes, day(n));
    }

    // Monday morning, well past the grace window for all three days.
    let engine = vault_at(&tmp.path().join("vault"), at(day(4), 9, TZ));
    ops::ingest(&engine, &notes).expect("ingest");

    let report = ops::seal_due(&engine, 6, 30).expect("seal_due");
    assert_eq!(report.sealed, vec![day(1), day(2), day(3)]);

    // And the chain agrees: seq in date order, no gaps.
    let sealed = engine.store().all_footage(engine.dek().unwrap()).unwrap();
    assert_eq!(sealed.len(), 3);
    for (index, footage) in sealed.iter().enumerate() {
        assert_eq!(footage.seq, u64::try_from(index).unwrap() + 1);
        assert_eq!(footage.date, day(u32::try_from(index).unwrap() + 1));
    }
    ops::verify(&engine)
        .expect("verify")
        .chain_ok
        .then_some(())
        .expect("chain must verify");
}

/// Today is never sealed. It is not over.
///
/// Tested with **no grace window at all**, deliberately. With the default six
/// hours, today is protected by grace rather than by being today — so a version
/// that started its walk at the current day would still pass, and the property
/// this test is named for would not be tested by it.
#[test]
fn the_current_day_is_left_alone() {
    let tmp = tempfile::tempdir().unwrap();
    let notes = tmp.path().join("notes");
    write_note(&notes, day(1));
    write_note(&notes, day(2));

    // Late on the 2nd — the 1st is long done, the 2nd is still being lived.
    let engine = vault_at(&tmp.path().join("vault"), at(day(2), 23, TZ));
    ops::ingest(&engine, &notes).expect("ingest");

    let report = ops::seal_due(&engine, 0, 30).expect("seal_due");
    assert_eq!(report.sealed, vec![day(1)]);
    assert!(
        engine.store().date_is_sealed(day(2)).unwrap().is_none(),
        "the day the user is still living was sealed"
    );
}

/// A day inside its grace window waits, and says it is waiting.
///
/// People write the day up afterwards. Sealing at the stroke of midnight
/// strands those notes as amendments to a day that is already closed (I2).
#[test]
fn a_day_still_in_its_grace_window_is_not_sealed_yet() {
    let tmp = tempfile::tempdir().unwrap();
    let notes = tmp.path().join("notes");
    write_note(&notes, day(1));

    // 02:00 the next morning: the 1st ended two hours ago, grace is six.
    let engine = vault_at(&tmp.path().join("vault"), at(day(2), 2, TZ));
    ops::ingest(&engine, &notes).expect("ingest");

    let early = ops::seal_due(&engine, 6, 30).expect("seal_due");
    assert!(early.sealed.is_empty());
    assert_eq!(
        early.waiting_on_grace,
        Some(day(1)),
        "a day held back must say so, or `nothing happened` and `waiting` look alike"
    );

    // 09:00, past grace: now it seals.
    let later = vault_at(&tmp.path().join("vault"), at(day(2), 9, TZ));
    let report = ops::seal_due(&later, 6, 30).expect("seal_due");
    assert_eq!(report.sealed, vec![day(1)]);
}

/// A note written after the cutoff but inside grace lands in the right day.
///
/// This is the whole reason grace exists, so it is tested as behaviour rather
/// than as a timestamp comparison.
#[test]
fn a_late_note_still_lands_in_the_day_it_describes() {
    let tmp = tempfile::tempdir().unwrap();
    let notes = tmp.path().join("notes");

    // Nothing written on the 1st yet. At 01:00 on the 2nd, seal_due holds off.
    let engine = vault_at(&tmp.path().join("vault"), at(day(2), 1, TZ));
    assert!(
        ops::seal_due(&engine, 6, 30)
            .expect("seal_due")
            .sealed
            .is_empty()
    );

    // The user writes up the 1st before going to bed.
    write_note(&notes, day(1));
    let engine = vault_at(&tmp.path().join("vault"), at(day(2), 2, TZ));
    ops::ingest(&engine, &notes).expect("ingest");

    // Morning: the day seals with the note in it, not as an amendment.
    let morning = vault_at(&tmp.path().join("vault"), at(day(2), 9, TZ));
    let report = ops::seal_due(&morning, 6, 30).expect("seal_due");
    assert_eq!(report.sealed, vec![day(1)]);

    let footage = morning
        .store()
        .get_footage(morning.dek().unwrap(), 1)
        .unwrap()
        .expect("day 1");
    assert!(!footage.empty, "the late note did not make it into the day");
}

/// Backfill is bounded, so a long-idle vault does not seal a year on launch.
#[test]
fn backfill_stops_at_the_configured_limit() {
    let tmp = tempfile::tempdir().unwrap();
    // Nothing sealed, and "today" is far from the vault's genesis.
    let engine = vault_at(&tmp.path().join("vault"), at(day(28), 12, TZ));

    let report = ops::seal_due(&engine, 6, 3).expect("seal_due");
    assert_eq!(report.sealed.len(), 3, "backfill ignored its limit");
    // The most recent three days, not the oldest three: a month of silence is
    // a fact about that month, and filling it in silently would hide it.
    assert_eq!(report.sealed, vec![day(25), day(26), day(27)]);
}

/// A day from before the vault existed is never sealed.
///
/// A fresh vault walking its whole backfill window would seal a month it was
/// never there for — history invented rather than recorded.
#[test]
fn days_before_genesis_are_not_sealed() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("vault");
    let (engine, _) = Engine::init(&dir, &passphrase(), TZ, None, None, cheap()).expect("init");
    // Genesis on the 10th; "today" is the 12th.
    engine
        .store()
        .set_meta(
            ghostr_store::schema::meta_key::CREATED_AT,
            &at(day(10), 12, TZ).utc_millis().to_string(),
        )
        .expect("genesis");
    drop(engine);

    let engine = Engine::open_with(
        &dir,
        &passphrase(),
        Some(Box::new(FixedClock::at(at(day(12), 9, TZ), TZ))),
        Some(Box::new(SeededRng::from_seed(7))),
    )
    .expect("open");

    // The 11th is sealable. The 10th is genesis day and everything before it is
    // not this chain's to speak for.
    let report = ops::seal_due(&engine, 6, 30).expect("seal_due");
    assert_eq!(report.sealed, vec![day(10), day(11)]);
}

/// Running twice does nothing the second time.
#[test]
fn a_second_pass_seals_nothing() {
    let tmp = tempfile::tempdir().unwrap();
    let notes = tmp.path().join("notes");
    write_note(&notes, day(1));

    let engine = vault_at(&tmp.path().join("vault"), at(day(2), 9, TZ));
    ops::ingest(&engine, &notes).expect("ingest");

    assert_eq!(
        ops::seal_due(&engine, 6, 30).expect("first").sealed.len(),
        1
    );
    assert!(
        ops::seal_due(&engine, 6, 30)
            .expect("second")
            .sealed
            .is_empty()
    );
}

/// A replica seals nothing, however many days are outstanding.
///
/// The guard is in `memoria`, and this is what proves auto-seal cannot route
/// around it — a replica running `serve` all night must not quietly fork the
/// chain (I3, SPEC §14 Q10).
#[test]
fn a_replica_seals_nothing() {
    let tmp = tempfile::tempdir().unwrap();
    let notes = tmp.path().join("notes");
    write_note(&notes, day(1));
    write_note(&notes, day(2));

    let engine = vault_at(&tmp.path().join("vault"), at(day(3), 9, TZ));
    ops::ingest(&engine, &notes).expect("ingest");
    engine.set_device_role(DeviceRole::Replica).expect("role");

    assert!(ops::seal_due(&engine, 6, 30).is_err());
    assert!(engine.store().date_is_sealed(day(1)).unwrap().is_none());
}
