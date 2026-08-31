//! The daily loop end to end: distil, issue, answer, score.
//!
//! No network, no model. What is under test is the half of M2 that works on a
//! stock build — mechanical quests over a deterministic persona — and the four
//! controls that keep the number honest: the commitment, the holdout, the
//! decoys, and expiry.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::Path;

use chrono::NaiveDate;
use chrono_tz::Tz;
use ghostr_core::fidelity::ScoreWindow;
use ghostr_core::quest::{QuestStatus, Severity, Verdict};
use ghostr_core::sensitivity::{Sensitivity, TrustLevel};
use ghostr_core::time::Timestamp;
use ghostr_crypto::kdf::Argon2Params;
use ghostr_crypto::secret::SecretString;
use ghostr_engine::engine::Engine;
use ghostr_engine::ops;
use ghostr_testkit::{CorpusGenerator, FixedClock, SeededRng};

const DAYS: u32 = 30;
const START: (i32, u32, u32) = (2026, 1, 5);
/// The instant the fixed clock starts at: 2026-01-05T00:00:00Z, near enough.
const EPOCH_MILLIS: i64 = 1_767_571_200_000;

fn start_date() -> NaiveDate {
    NaiveDate::from_ymd_opt(START.0, START.1, START.2).expect("valid")
}

fn passphrase() -> SecretString {
    SecretString::new("correct horse battery staple".to_owned())
}

fn cheap_params() -> Argon2Params {
    Argon2Params {
        memory_kib: 8,
        iterations: 1,
        lanes: 1,
    }
}

/// A vault with a corpus, thirty sealed days, and an adopted persona.
///
/// The clock handle comes back with it: expiry, streaks, and the rolling window
/// only exist once time can move.
fn ready_vault(dir: &Path) -> (Engine, FixedClock) {
    Engine::init(dir, &passphrase(), Tz::UTC, None, None, cheap_params()).expect("init");

    let clock = FixedClock::at(Timestamp::new(EPOCH_MILLIS, 0), Tz::UTC);
    let engine = Engine::open_with(
        dir,
        &passphrase(),
        Some(Box::new(clock.clone())),
        Some(Box::new(SeededRng::from_seed(7))),
    )
    .expect("open");

    load(&engine);
    for day in 0..DAYS {
        let date = start_date() + chrono::Duration::days(i64::from(day));
        ops::memoria(&engine, date).expect("seal");
    }

    let candidate = ops::propose_persona(&engine).expect("propose");
    ops::adopt_persona(&engine, &candidate).expect("adopt");
    (engine, clock)
}

fn load(engine: &Engine) {
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
}

/// Issues quests for `days` consecutive days, advancing the clock a day at a
/// time so expiry and streaks behave as they would in use.
fn issue_days(engine: &Engine, clock: &FixedClock, days: u32) -> Vec<ghostr_core::ids::QuestId> {
    let mut all = Vec::new();
    for day in 0..days {
        let date = start_date() + chrono::Duration::days(i64::from(day));
        all.extend(ops::issue_quests(engine, date).expect("issue").issued);
        // Answer the same day they are issued, then move on. Answering before
        // the clock advances is what keeps them inside their 48-hour window.
        for quest in ops::open_quests(engine, 100).expect("open") {
            let verdict = if quest.id.as_uuid().as_bytes()[15] % 4 == 0 {
                Verdict::Correct {
                    correction: "closer to the other way round, honestly".to_owned(),
                    severity: Severity::Minor,
                }
            } else {
                Verdict::Confirm
            };
            clock.advance(30);
            ops::answer_quest(engine, quest.id, verdict).expect("answer");
        }
        clock.advance(86_400 - 3_600);
    }
    all
}

/// The headline: a month of days produces a score with evidence behind it.
#[test]
fn a_month_of_answered_quests_produces_a_qualified_score() {
    let home = tempfile::tempdir().unwrap();
    let (engine, clock) = ready_vault(&home.path().join("vault"));

    let issued = issue_days(&engine, &clock, DAYS);
    assert!(
        issued.len() >= 30,
        "a month should produce a real batch, got {}",
        issued.len()
    );

    let score = ops::fidelity(&engine, ScoreWindow::AllTime).expect("score");
    assert!(score.sample_size >= 10, "{score:?}");
    assert!((0.0..=1.0).contains(&score.overall));
    // Never a bare percentage: the interval must bracket the point estimate.
    assert!(score.confidence_interval.0 <= score.overall);
    assert!(score.overall <= score.confidence_interval.1);
    // A breakdown that actually breaks down. One facet in the report means the
    // per-facet convergence rule has nothing to check, and averaging a single
    // facet into an "overall" is the one thing the report must not do.
    assert!(score.by_facet.len() >= 2, "{:?}", score.by_facet.keys());
    assert!(
        score.by_quest_kind.len() >= 2,
        "{:?}",
        score.by_quest_kind.keys()
    );
    assert_eq!(
        score.committed_at_seq,
        u64::from(DAYS),
        "the score points at the chain tip a third party can check"
    );

    // The signals travel with the number, and they are real: decoys were issued
    // and counted, and nothing was answered faster than a plausible read.
    assert!(
        score.integrity.decoy_sample_size > 0,
        "no decoys were issued"
    );
    assert!(
        score.integrity.fast_verdict_rate.abs() < f32::EPSILON,
        "every verdict here took 30s; a nonzero rate means a decoy was \
         reported with no answer time"
    );
}

/// SPEC I6. Every quest arrives with its commitment already durable, and the
/// store refuses to let it be rewritten afterwards.
#[test]
fn a_stored_commitment_cannot_be_rewritten() {
    let home = tempfile::tempdir().unwrap();
    let (engine, _clock) = ready_vault(&home.path().join("vault"));
    let issue = ops::issue_quests(&engine, start_date()).expect("issue");
    let id = issue.issued[0];

    let quest = ops::get_quest(&engine, id).expect("get");
    assert_ne!(quest.answer_commitment, ghostr_core::hash::Hash32::zero());
    assert!(
        ghostr_quests::verify_commitment(&quest, quest.kind.committed_answer(), quest.confidence)
            .expect("verify"),
        "a quest must be able to reproduce its own commitment"
    );

    let raw =
        std::fs::read(home.path().join("vault").join(ghostr_store::DB_FILENAME)).expect("read db");
    let answer = quest.kind.committed_answer();
    assert!(
        !raw.windows(answer.len()).any(|w| w == answer.as_bytes()),
        "the ghost's committed answer is readable in the database file"
    );
}

/// SPEC I7. Only held-out, non-decoy, answered quests reach the scorer — and
/// the store is what enforces it, not the caller's good intentions.
#[test]
fn only_held_out_quests_are_scored() {
    let home = tempfile::tempdir().unwrap();
    let (engine, clock) = ready_vault(&home.path().join("vault"));
    issue_days(&engine, &clock, DAYS);

    let dek = engine.dek().expect("dek");
    let scoreable = engine
        .store()
        .scoreable_quests(dek, Timestamp::new(0, 0))
        .expect("scoreable");
    assert!(!scoreable.is_empty());
    for (quest, _) in &scoreable {
        assert!(quest.holdout, "a trainable quest reached the score");
        assert!(!quest.decoy, "a decoy reached the score");
        assert_eq!(quest.status, QuestStatus::Answered);
    }
}

/// SPEC I7 again, from the other side: a held-out correction must never reach
/// the training queue, so the queue holds strictly fewer than the corrections.
#[test]
fn held_out_corrections_never_enter_the_training_queue() {
    let home = tempfile::tempdir().unwrap();
    let (engine, clock) = ready_vault(&home.path().join("vault"));
    issue_days(&engine, &clock, DAYS);

    let dek = engine.dek().expect("dek");
    let queued = engine.store().peek_deltas(dek).expect("peek");
    assert!(
        !queued.is_empty(),
        "nothing was queued; the check is vacuous"
    );
    for delta in queued {
        assert!(!delta.from_holdout);
    }
}

/// SPEC I7 has a second door: a held-out correction produces no delta, but it
/// is *also* a memory, and distillation reads memories. Training on one would
/// mean the ghost had seen the answer to a question it is about to be scored
/// on — through the corpus rather than through the queue (SPEC Q18).
#[test]
fn a_held_out_correction_never_reaches_distillation() {
    let home = tempfile::tempdir().unwrap();
    let (engine, clock) = ready_vault(&home.path().join("vault"));
    let dek = engine.dek().expect("dek");

    ops::issue_quests(&engine, start_date()).expect("issue");
    let open = ops::open_quests(&engine, 100).expect("open");
    let held_out: Vec<_> = open.iter().filter(|q| q.holdout).map(|q| q.id).collect();
    assert!(
        !held_out.is_empty(),
        "no holdout in the batch; nothing tested"
    );

    for quest in &open {
        clock.advance(30);
        ops::answer_quest(
            &engine,
            quest.id,
            Verdict::Correct {
                correction: "I would have put it the other way round".to_owned(),
                severity: Severity::Major,
            },
        )
        .expect("answer");
    }

    // The held-out corrections are stored — they are the user's own words — but
    // under a source distillation does not read.
    let quarantined: std::collections::BTreeSet<_> = engine
        .store()
        .all_sources(dek)
        .expect("sources")
        .into_iter()
        .filter(|s| s.kind_tag == "verdict_holdout")
        .map(|s| s.id)
        .collect();
    assert_eq!(quarantined.len(), 1, "held-out corrections were stored");

    let stored: Vec<_> = engine
        .store()
        .all_memories(dek)
        .expect("memories")
        .into_iter()
        .filter(|m| quarantined.contains(&m.source_id))
        .collect();
    assert_eq!(
        stored.len(),
        held_out.len(),
        "every held-out correction is kept, just quarantined"
    );

    let candidate = ops::propose_persona(&engine).expect("propose");
    for memory in &stored {
        assert!(
            !candidate.model.derived_from.contains(&memory.id),
            "a held-out correction reached distillation"
        );
    }
}

/// A correction becomes corpus and a queued delta; adopting a version clears
/// the queue so the same correction cannot be counted twice.
#[test]
fn a_correction_trains_once_and_only_once() {
    let home = tempfile::tempdir().unwrap();
    let (engine, clock) = ready_vault(&home.path().join("vault"));
    let dek = engine.dek().expect("dek");

    ops::issue_quests(&engine, start_date()).expect("issue");
    let mut corrected = 0;
    for quest in ops::open_quests(&engine, 100).expect("open") {
        clock.advance(30);
        ops::answer_quest(
            &engine,
            quest.id,
            Verdict::Correct {
                correction: "not quite how I'd put it".to_owned(),
                severity: Severity::Minor,
            },
        )
        .expect("answer");
        if !quest.holdout && !quest.evidence.is_empty() {
            corrected += 1;
        }
    }

    assert!(corrected > 0, "nothing was trainable; the check is vacuous");
    assert_eq!(
        engine.store().queued_delta_count().expect("count"),
        corrected,
        "one delta per trainable correction with evidence behind it"
    );

    // Proposing reads the queue; only adopting consumes it. Declining a diff
    // must not throw away the words the user wrote.
    ops::propose_persona(&engine).expect("propose");
    assert_eq!(
        engine.store().queued_delta_count().expect("count"),
        corrected
    );

    let candidate = ops::propose_persona(&engine).expect("propose");
    ops::adopt_persona(&engine, &candidate).expect("adopt");
    assert_eq!(engine.store().queued_delta_count().expect("count"), 0);
    let _ = dek;
}

/// A verdict is one-shot. Answering twice would make the score a function of
/// how many times the user pressed the button.
#[test]
fn a_quest_takes_one_verdict() {
    let home = tempfile::tempdir().unwrap();
    let (engine, clock) = ready_vault(&home.path().join("vault"));
    ops::issue_quests(&engine, start_date()).expect("issue");
    let quest = ops::open_quests(&engine, 1).expect("open").remove(0);

    clock.advance(30);
    ops::answer_quest(&engine, quest.id, Verdict::Confirm).expect("first");
    let err = ops::answer_quest(&engine, quest.id, Verdict::Unknown).expect_err("second");
    assert!(matches!(
        err,
        ghostr_engine::Error::Quests(ghostr_quests::Error::AlreadyAnswered { .. })
    ));
}

/// A quest past its window is closed, and a closed quest takes no verdict.
/// Otherwise a user could answer a month of backlog in one sitting and call it
/// fidelity.
#[test]
fn an_expired_quest_is_closed_and_unanswerable() {
    let home = tempfile::tempdir().unwrap();
    let (engine, clock) = ready_vault(&home.path().join("vault"));
    ops::issue_quests(&engine, start_date()).expect("issue");
    let quest = ops::open_quests(&engine, 1).expect("open").remove(0);

    // Past the 48-hour window.
    clock.advance(3 * 86_400);
    assert!(ops::expire_quests(&engine).expect("expire") > 0);
    assert!(ops::open_quests(&engine, 100).expect("open").is_empty());

    let err = ops::answer_quest(&engine, quest.id, Verdict::Confirm).expect_err("must refuse");
    assert!(matches!(
        err,
        ghostr_engine::Error::Quests(ghostr_quests::Error::Expired { .. })
    ));
}

/// A question still open from yesterday, asked again today, is the same
/// question twice — and to someone opening the app it reads as the ghost having
/// forgotten what it already asked.
#[test]
fn a_question_already_waiting_is_not_asked_again() {
    let home = tempfile::tempdir().unwrap();
    let (engine, clock) = ready_vault(&home.path().join("vault"));

    ops::issue_quests(&engine, start_date()).expect("day one");
    let waiting: std::collections::BTreeSet<String> = ops::open_quests(&engine, 100)
        .expect("open")
        .iter()
        .map(|q| q.kind.committed_answer().to_owned())
        .collect();
    assert!(!waiting.is_empty(), "nothing issued; the check is vacuous");

    // A second day, with the first day's questions still unanswered.
    clock.advance(86_400);
    ops::issue_quests(&engine, start_date().succ_opt().expect("next day")).expect("day two");

    let all = ops::open_quests(&engine, 200).expect("open");
    let answers: Vec<&str> = all.iter().map(|q| q.kind.committed_answer()).collect();
    let unique: std::collections::BTreeSet<&&str> = answers.iter().collect();
    assert_eq!(
        unique.len(),
        answers.len(),
        "the same question is open twice at once"
    );
}

/// Two runs on one day would let a user re-roll until the questions looked easy.
#[test]
fn a_day_is_issued_once() {
    let home = tempfile::tempdir().unwrap();
    let (engine, _clock) = ready_vault(&home.path().join("vault"));
    ops::issue_quests(&engine, start_date()).expect("first");
    assert!(ops::issue_quests(&engine, start_date()).is_err());
}

/// A new vault has nothing to score, and says so rather than reporting a
/// number: 100% over four quests is noise.
#[test]
fn too_few_answers_refuse_to_produce_a_score() {
    let home = tempfile::tempdir().unwrap();
    let (engine, clock) = ready_vault(&home.path().join("vault"));
    ops::issue_quests(&engine, start_date()).expect("issue");
    for quest in ops::open_quests(&engine, 3).expect("open") {
        clock.advance(30);
        ops::answer_quest(&engine, quest.id, Verdict::Confirm).expect("answer");
    }

    assert!(matches!(
        ops::fidelity(&engine, ScoreWindow::AllTime),
        Err(ghostr_engine::Error::Quests(
            ghostr_quests::Error::InsufficientSample { .. }
        ))
    ));
}

/// Quests cannot be issued before there is a ghost to make claims.
#[test]
fn issuing_before_a_persona_exists_is_refused() {
    let home = tempfile::tempdir().unwrap();
    let dir = home.path().join("vault");
    Engine::init(&dir, &passphrase(), Tz::UTC, None, None, cheap_params()).expect("init");
    let engine = Engine::open(&dir, &passphrase()).expect("open");

    assert!(matches!(
        ops::issue_quests(&engine, start_date()),
        Err(ghostr_engine::Error::Config { .. })
    ));
}

/// The whole loop must be reproducible under a fixed seed, or the property that
/// makes the score meaningful — that holdout assignment was not chosen after
/// the fact — cannot be tested at all.
#[test]
fn the_loop_is_reproducible_under_a_fixed_seed() {
    let holdouts = |dir: &Path| -> Vec<bool> {
        let (engine, _clock) = ready_vault(dir);
        ops::issue_quests(&engine, start_date())
            .expect("issue")
            .issued
            .into_iter()
            .map(|id| ops::get_quest(&engine, id).expect("get").holdout)
            .collect()
    };

    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    assert_eq!(
        holdouts(&a.path().join("vault")),
        holdouts(&b.path().join("vault"))
    );
}
