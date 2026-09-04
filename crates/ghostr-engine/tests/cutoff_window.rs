//! Which memories a day's footage actually contains.
//!
//! `cutoff_minute_of_day` is in `config.toml`, is documented in SPEC §1 as "a
//! configurable cutoff (default: end of day, local time)", and defaults to
//! 23:59. This file is what checks that the number does something.
//!
//! It exists because a sweep for functions with no production caller found
//! `ghostr_memoria::cutoff::window_for` — the code that honours the policy —
//! called by nothing but its own tests, while the engine computed a hardcoded
//! midnight-to-midnight window of its own. Two implementations of one rule, and
//! the tested one was not the one that ran.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::Path;

use chrono::NaiveDate;
use chrono_tz::Tz;
use ghostr_core::ids::{MemoryId, SourceId};
use ghostr_core::memory::{Memory, MemoryBody, MemoryKind, Provenance};
use ghostr_core::sensitivity::{Sensitivity, TrustLevel};
use ghostr_core::time::Timestamp;
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

/// A vault whose cutoff is noon, so "which side of the cutoff" is unmissable.
///
/// Noon rather than the 23:59 default because a boundary an hour from midnight
/// is a boundary a bug can straddle by accident; one in the middle of the day
/// cannot.
fn vault_with_cutoff(dir: &Path, minute_of_day: u16) -> Engine {
    let (engine, _) =
        Engine::init(dir, &passphrase(), Tz::UTC, None, None, test_params()).expect("init");
    drop(engine);

    std::fs::write(
        dir.join(ghostr_engine::config::CONFIG_FILENAME),
        format!("cutoff_minute_of_day = {minute_of_day}\n"),
    )
    .expect("write config");

    Engine::open(dir, &passphrase()).expect("reopen")
}

fn source(engine: &Engine) -> SourceId {
    let id = SourceId::new(1, [1u8; 10]);
    engine
        .store()
        .upsert_source_with(
            engine.dek().expect("dek"),
            &ghostr_store::sqlite::NewSourceRow {
                id,
                kind_tag: "markdown_vault",
                config: "{\"location\":\"/notes\"}",
                trust: TrustLevel::FirstParty,
                sensitivity: Sensitivity::Private,
            },
            [2u8; 24],
        )
        .expect("source");
    id
}

/// A memory that happened at `hour:00` UTC on `date`.
fn at(engine: &Engine, src: SourceId, date: NaiveDate, hour: u32, text: &str) -> MemoryId {
    let when = date.and_hms_opt(hour, 0, 0).unwrap().and_utc();
    let millis = when.timestamp_millis();
    let memory = Memory {
        id: MemoryId::new(millis.unsigned_abs(), [u8::try_from(hour).unwrap_or(0); 10]),
        source_id: src,
        occurred_at: Some(Timestamp::new(millis, 0)),
        ingested_at: Timestamp::new(millis, 0),
        kind: MemoryKind::Utterance,
        body: MemoryBody {
            text: text.to_owned(),
            structured: None,
            redactions: Vec::new(),
        },
        entities: Vec::new(),
        salience: 0.5,
        sensitivity: Sensitivity::Private,
        provenance: Provenance {
            source_id: src,
            external_id: Some(format!("{date}T{hour:02}")),
            url: None,
            raw_hash: ghostr_core::hash::tagged_hash(
                ghostr_core::hash::Tag::MemoryLeaf,
                format!("{date}T{hour:02}").as_bytes(),
            ),
        },
        salt: [u8::try_from(hour).unwrap_or(0); 32],
        supersedes: None,
        embedding: None,
    };
    let id = memory.id;
    engine
        .store()
        .put_memory(engine.dek().expect("dek"), &memory, engine.nonce())
        .expect("put");
    id
}

fn day(d: u32) -> NaiveDate {
    NaiveDate::from_ymd_opt(2026, 8, d).unwrap()
}

/// The configured cutoff decides which day a memory is sealed into.
///
/// With a noon cutoff, the footage dated the 24th covers
/// `[23rd 12:00, 24th 12:00)`. A note written at 13:00 on the 24th is after
/// that cutoff and belongs to the 25th — which is the whole point of being able
/// to set one.
#[test]
fn a_configured_cutoff_decides_which_day_a_memory_lands_in() {
    let home = tempfile::tempdir().unwrap();
    let vault = home.path().join("vault");
    let engine = vault_with_cutoff(&vault, 12 * 60);
    let src = source(&engine);

    let before = at(&engine, src, day(24), 11, "written before the cutoff");
    let after = at(&engine, src, day(24), 13, "written after the cutoff");

    ops::memoria(&engine, day(24)).expect("seal the 24th");
    let sealed = ops::recap(&engine, day(24)).expect("recap").footage;

    assert!(
        sealed.memory_ids.contains(&before),
        "a note before the cutoff belongs to this day"
    );
    assert!(
        !sealed.memory_ids.contains(&after),
        "a note after the cutoff belongs to the next day, not this one"
    );

    // And it is not lost: the next day picks it up, so the two windows abut
    // rather than leaving a hole (I3 — there are no gaps).
    ops::memoria(&engine, day(25)).expect("seal the 25th");
    let next = ops::recap(&engine, day(25)).expect("recap").footage;
    assert!(
        next.memory_ids.contains(&after),
        "a note after the cutoff must land in the following day"
    );
}

/// Consecutive days abut exactly: one day's end is the next day's start.
///
/// A gap would silently drop every memory that fell in it — never sealed, never
/// in any footage, and invisible because nothing would report a day as short.
#[test]
fn consecutive_windows_leave_no_gap_and_no_overlap() {
    let home = tempfile::tempdir().unwrap();
    let vault = home.path().join("vault");
    let engine = vault_with_cutoff(&vault, 12 * 60);
    let src = source(&engine);

    // One memory per hour across three days, so any gap or overlap in the
    // windows shows up as a memory sealed twice or not at all.
    let mut all: Vec<(MemoryId, i64)> = Vec::new();
    for d in 23..=26u32 {
        for hour in [0, 6, 11, 12, 13, 18, 23] {
            let id = at(&engine, src, day(d), hour, &format!("{d} at {hour}"));
            let millis = day(d)
                .and_hms_opt(hour, 0, 0)
                .unwrap()
                .and_utc()
                .timestamp_millis();
            all.push((id, millis));
        }
    }

    let mut seen: Vec<MemoryId> = Vec::new();
    for d in 24..=26u32 {
        ops::memoria(&engine, day(d)).expect("seal");
        seen.extend(
            ops::recap(&engine, day(d))
                .expect("recap")
                .footage
                .memory_ids,
        );
    }

    let unique: std::collections::BTreeSet<_> = seen.iter().copied().collect();
    assert_eq!(
        unique.len(),
        seen.len(),
        "a memory was sealed into two days: the windows overlap"
    );

    // Everything strictly inside [23rd 12:00, 26th 12:00) must appear exactly
    // once. Anything outside is simply not in the sealed range yet.
    let start = day(23)
        .and_hms_opt(12, 0, 0)
        .unwrap()
        .and_utc()
        .timestamp_millis();
    let end = day(26)
        .and_hms_opt(12, 0, 0)
        .unwrap()
        .and_utc()
        .timestamp_millis();
    let expected: Vec<MemoryId> = all
        .iter()
        .filter(|(_, millis)| *millis >= start && *millis < end)
        .map(|(id, _)| *id)
        .collect();
    for id in &expected {
        assert!(
            unique.contains(id),
            "a memory inside the sealed range reached no footage: the windows leave a gap"
        );
    }
}

/// The default is 23:59, and it is a real cutoff rather than midnight.
///
/// SPEC §1 says the default cutoff is "end of day, local time". A vault that
/// wrote no config at all must still behave that way.
///
/// Both assertions are needed. "23:59:30 is not in the 24th" holds under a
/// midnight window too — that window is `[23rd 00:00, 24th 00:00)` and contains
/// neither note — so on its own it would pass against the very bug this file
/// exists to catch. The pair only holds at 23:59.
#[test]
fn the_default_cutoff_is_not_midnight() {
    let home = tempfile::tempdir().unwrap();
    let vault = home.path().join("vault");
    let (engine, _) =
        Engine::init(&vault, &passphrase(), Tz::UTC, None, None, test_params()).expect("init");
    let src = source(&engine);

    let early = minute(&engine, src, day(24), 23, 58, "before the cutoff");
    let late = minute(&engine, src, day(24), 23, 59, "after the cutoff");

    ops::memoria(&engine, day(24)).expect("seal");
    let sealed = ops::recap(&engine, day(24)).expect("recap").footage;

    assert!(
        sealed.memory_ids.contains(&early),
        "23:58 is inside the default 23:59 cutoff and belongs to this day"
    );
    assert!(
        !sealed.memory_ids.contains(&late),
        "23:59 is at the default cutoff and belongs to the next day"
    );
}

/// A memory at `hour:minute` UTC on `date`.
fn minute(
    engine: &Engine,
    src: SourceId,
    date: NaiveDate,
    hour: u32,
    min: u32,
    text: &str,
) -> MemoryId {
    let millis = date
        .and_hms_opt(hour, min, 0)
        .unwrap()
        .and_utc()
        .timestamp_millis();
    let tag = format!("{date}T{hour:02}:{min:02}");
    let memory = Memory {
        id: MemoryId::new(millis.unsigned_abs(), [u8::try_from(min).unwrap_or(0); 10]),
        source_id: src,
        occurred_at: Some(Timestamp::new(millis, 0)),
        ingested_at: Timestamp::new(millis, 0),
        kind: MemoryKind::Utterance,
        body: MemoryBody {
            text: text.to_owned(),
            structured: None,
            redactions: Vec::new(),
        },
        entities: Vec::new(),
        salience: 0.5,
        sensitivity: Sensitivity::Private,
        provenance: Provenance {
            source_id: src,
            external_id: Some(tag.clone()),
            url: None,
            raw_hash: ghostr_core::hash::tagged_hash(
                ghostr_core::hash::Tag::MemoryLeaf,
                tag.as_bytes(),
            ),
        },
        salt: [u8::try_from(min).unwrap_or(0); 32],
        supersedes: None,
        embedding: None,
    };
    let id = memory.id;
    engine
        .store()
        .put_memory(engine.dek().expect("dek"), &memory, engine.nonce())
        .expect("put");
    id
}
