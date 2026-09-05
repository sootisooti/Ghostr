//! A pending proof becomes a confirmed one, through the engine.
//!
//! # No network, and the calendar is the fake part on purpose
//!
//! CLAUDE.md §4.8 bans network calls in tests, and a real OpenTimestamps
//! calendar needs hours to get its aggregate into a Bitcoin block — nothing a
//! suite can wait for. The `CalendarFetch` seam exists so the *merge* and the
//! record-keeping, which are the parts that can silently corrupt a proof or
//! claim an attestation that does not exist, run here with recorded bytes.
//!
//! # The gap this closes
//!
//! M0's exit criterion "a day sealed today is OTS-confirmed within 24h" has been
//! unchecked since M0, and `AnchorRecordState::Confirmed` was reachable from no
//! production path at all: `submit` stored a calendar attestation and nothing
//! ever asked whether it had landed. Every anchored day read "pending" for ever.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::Path;

use chrono_tz::Tz;
use ghostr_anchor::ots::CalendarFetch;
use ghostr_core::hash::Hash32;
use ghostr_crypto::kdf::Argon2Params;
use ghostr_crypto::secret::SecretString;
use ghostr_engine::engine::Engine;
use ghostr_engine::ops;
use ghostr_store::sqlite::{AnchorRecord, AnchorRecordState};

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

fn vault(dir: &Path) -> Engine {
    std::fs::create_dir_all(dir.join("notes")).unwrap();
    std::fs::write(
        dir.join("notes/2026-08-24-monday.md"),
        "---\ndate: 2026-08-24\n---\nSealed a day so there is a tip to anchor.\n",
    )
    .unwrap();
    let (engine, _) =
        Engine::init(dir, &passphrase(), Tz::UTC, None, None, test_params()).expect("init");
    engine
}

/// A `.ots` carrying one pending attestation, exactly as `submit` stores it.
fn pending_proof(digest: Hash32, uri: &str) -> Vec<u8> {
    use opentimestamps::DetachedTimestampFile;
    use opentimestamps::attestation::Attestation;
    use opentimestamps::ser::DigestType;
    use opentimestamps::timestamp::{Step, StepData, Timestamp as OtsTimestamp};

    let file = DetachedTimestampFile {
        digest_type: DigestType::Sha256,
        timestamp: OtsTimestamp {
            start_digest: digest.as_bytes().to_vec(),
            first_step: Step {
                data: StepData::Attestation(Attestation::Pending {
                    uri: uri.to_owned(),
                }),
                output: digest.as_bytes().to_vec(),
                next: Vec::new(),
            },
        },
    };
    let mut out = Vec::new();
    file.to_writer(&mut out).expect("write");
    out
}

/// What a calendar returns once its aggregate is in a block.
fn in_a_block(height: usize) -> Vec<u8> {
    use opentimestamps::attestation::Attestation;
    use opentimestamps::ser::Serializer;

    let mut out = Vec::new();
    {
        let mut ser = Serializer::new(&mut out);
        ser.write_byte(0x00).expect("tag");
        Attestation::Bitcoin { height }
            .serialize(&mut ser)
            .expect("serialize");
    }
    out
}

struct Calendar(Result<Vec<u8>, String>);
impl CalendarFetch for Calendar {
    fn fetch(&self, _uri: &str, _commitment: &[u8]) -> Result<Vec<u8>, String> {
        self.0.clone()
    }
}

/// Seals a day and files a pending anchor for its tip.
fn sealed_with_pending_anchor(engine: &Engine, uri: &str) -> (u64, Hash32) {
    let date = chrono::NaiveDate::from_ymd_opt(2026, 8, 24).unwrap();
    ops::memoria(engine, date).expect("seal");
    let tip = engine.store().tip().expect("tip").expect("a sealed day");

    engine
        .store()
        .put_anchor(&AnchorRecord {
            seq: tip.seq,
            state: AnchorRecordState::Pending,
            digest: tip.link,
            submitted_at: Some(engine.now()),
            block_height: None,
            attempts: 1,
            detail: Some(uri.to_owned()),
            ots: Some(pending_proof(tip.link, uri)),
        })
        .expect("put anchor");
    (tip.seq, tip.link)
}

/// The criterion, end to end: a calendar that reached a block confirms the day,
/// and the block height is recorded where `ghostr verify` and `status` read it.
#[test]
fn a_calendar_reaching_a_block_confirms_the_day() {
    let home = tempfile::tempdir().unwrap();
    let dir = home.path().join("vault");
    let engine = vault(&dir);
    let (seq, _) = sealed_with_pending_anchor(&engine, "https://alice.calendar");

    let report = ops::upgrade_anchors(&engine, &Calendar(Ok(in_a_block(886_123)))).expect("pass");

    assert_eq!(report.asked, 1);
    assert_eq!(report.confirmed, 1, "the day must be confirmed");
    assert_eq!(report.still_pending, 0);

    let stored = engine
        .store()
        .get_anchor(seq)
        .expect("read")
        .expect("a record");
    assert_eq!(stored.state, AnchorRecordState::Confirmed);
    assert_eq!(stored.block_height, Some(886_123));

    // The `.ots` beside the store is the part a third party can check without
    // the vault, so it has to have been rewritten too.
    let on_disk = std::fs::read(dir.join("anchors").join(format!("{seq}.ots"))).expect("proof");
    ghostr_anchor::ots::read_detached_file(&on_disk, stored.digest).expect("still a valid proof");
}

/// A calendar with nothing yet must change nothing at all.
///
/// This is the normal state for the hours after a seal. Marking the day
/// confirmed here would be a false claim of a Bitcoin attestation, and
/// rewriting the proof would risk a good file for no gain.
#[test]
fn a_calendar_with_nothing_yet_leaves_the_record_pending() {
    let home = tempfile::tempdir().unwrap();
    let dir = home.path().join("vault");
    let engine = vault(&dir);
    let (seq, _) = sealed_with_pending_anchor(&engine, "https://alice.calendar");
    let before = engine.store().get_anchor(seq).unwrap().unwrap();

    let report =
        ops::upgrade_anchors(&engine, &Calendar(Err("504 upstream".to_owned()))).expect("pass");

    assert_eq!(report.asked, 1);
    assert_eq!(report.confirmed, 0);
    assert_eq!(report.still_pending, 1);

    let after = engine.store().get_anchor(seq).unwrap().unwrap();
    assert_eq!(after.state, AnchorRecordState::Pending);
    assert_eq!(after.block_height, None);
    assert_eq!(after.ots, before.ots, "the stored proof must be untouched");
}

/// Past the window the calendars are left alone.
///
/// A calendar that has not reached a block in eight days is not going to, and
/// asking a free service forever is the rude version of a bug (SPEC §7.4).
#[test]
fn a_proof_older_than_the_window_is_no_longer_asked_about() {
    let home = tempfile::tempdir().unwrap();
    let dir = home.path().join("vault");
    let engine = vault(&dir);
    let (seq, _) = sealed_with_pending_anchor(&engine, "https://alice.calendar");

    // Backdate the submission past the window.
    let mut record = engine.store().get_anchor(seq).unwrap().unwrap();
    let nine_days_ago = engine.now().utc_millis() - 9 * 24 * 60 * 60 * 1000;
    record.submitted_at = Some(ghostr_core::time::Timestamp::new(nine_days_ago, 0));
    engine.store().put_anchor(&record).unwrap();

    let report = ops::upgrade_anchors(&engine, &Calendar(Ok(in_a_block(1)))).expect("pass");

    assert_eq!(report.abandoned, 1);
    assert_eq!(report.asked, 0, "a calendar past the window is not asked");
    assert_eq!(
        engine.store().get_anchor(seq).unwrap().unwrap().state,
        AnchorRecordState::Pending,
        "the day stays pending — the link is still valid, just unattested"
    );
}
