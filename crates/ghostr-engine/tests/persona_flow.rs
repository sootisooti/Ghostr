//! Distillation over a real vault: ingest, seal, distil, adopt, diff.
//!
//! No network, no model. What is under test is the deterministic half of the
//! persona — the half that works on day one with nothing installed.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::Path;

use chrono_tz::Tz;
use ghostr_core::sensitivity::TrustLevel;
use ghostr_core::time::Timestamp;
use ghostr_crypto::kdf::Argon2Params;
use ghostr_crypto::secret::SecretString;
use ghostr_engine::engine::Engine;
use ghostr_engine::ops;
use ghostr_testkit::{CorpusGenerator, FixedClock, SeededRng};

const DAYS: u32 = 30;

fn vault(dir: &Path) -> Engine {
    let (engine, _) = Engine::init(
        dir,
        &SecretString::new("correct horse battery staple".to_owned()),
        Tz::UTC,
        None,
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

/// Loads a synthetic corpus, marking its source with a trust level.
fn load(engine: &Engine, trust: TrustLevel) -> Vec<ghostr_core::memory::Memory> {
    let clock = FixedClock::at(Timestamp::new(1_767_000_000_000, 0), Tz::UTC);
    let corpus = CorpusGenerator::new(DAYS).generate(&clock, &SeededRng::from_seed(42));
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
                    trust,
                    sensitivity: ghostr_core::sensitivity::Sensitivity::Private,
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
    corpus.memories
}

fn seal_all(engine: &Engine) {
    let start = chrono::NaiveDate::from_ymd_opt(2026, 1, 5).unwrap();
    for day in 0..DAYS {
        let date = start + chrono::Duration::days(i64::from(day));
        ops::memoria(engine, date).expect("seal");
    }
}

#[test]
fn a_month_of_notes_distils_into_a_persona() {
    let home = tempfile::tempdir().unwrap();
    let engine = vault(&home.path().join("vault"));
    load(&engine, TrustLevel::FirstParty);
    seal_all(&engine);

    let candidate = ops::propose_persona(&engine).expect("propose");
    assert_eq!(candidate.model.version.ordinal, 1);
    assert!(candidate.replaces.is_none());

    // Voice is measured, so it is populated with no model involved.
    assert!(!candidate.model.facets.voice.lexicon.is_empty());
    assert!(!candidate.model.facets.voice.exemplars.is_empty());
    // The planted cast turns up.
    assert!(!candidate.model.facets.relationships.is_empty());
    // So do the planted routines. A recurring task reopens under the same title
    // every few days, and counting those reopenings is what makes "this keeps
    // happening" evidence rather than an assertion.
    assert!(
        !candidate.model.facets.routines.is_empty(),
        "the corpus plants routines; distillation must find them"
    );
    // And the facets a model would supply are empty rather than guessed.
    assert!(candidate.model.facets.opinions.is_empty());
}

/// Proposing must not adopt. Reading the diff first is the point of the two
/// steps, and a version taking effect because somebody ran a read-only-looking
/// command would defeat it.
#[test]
fn proposing_does_not_adopt() {
    let home = tempfile::tempdir().unwrap();
    let engine = vault(&home.path().join("vault"));
    load(&engine, TrustLevel::FirstParty);
    seal_all(&engine);

    ops::propose_persona(&engine).expect("propose");
    assert!(ops::persona_head(&engine).expect("head").is_none());

    let candidate = ops::propose_persona(&engine).expect("propose");
    ops::adopt_persona(&engine, &candidate).expect("adopt");
    assert!(ops::persona_head(&engine).expect("head").is_some());
}

/// Distillation is deterministic over the same corpus, which is what lets
/// `adopt` re-run it rather than caching a candidate.
#[test]
fn distilling_twice_over_the_same_corpus_gives_the_same_version() {
    let home = tempfile::tempdir().unwrap();
    let engine = vault(&home.path().join("vault"));
    load(&engine, TrustLevel::FirstParty);
    seal_all(&engine);

    let a = ops::propose_persona(&engine).expect("a");
    let b = ops::propose_persona(&engine).expect("b");
    assert_eq!(a.model.version.content, b.model.version.content);
}

/// A self-reported source feeds the claims and never the voice, end to end.
///
/// The unit tests in `ghostr-persona` hold the rule; this holds the *wiring*,
/// which is where it was wrong. `propose_persona` builds two slices from the
/// store's trust levels, and if it built one — as it did before this test
/// existed — a health or people log could evidence nothing at all, and the log
/// would be dead weight in the vault.
#[test]
fn a_self_reported_source_feeds_claims_but_never_the_voice() {
    use ghostr_core::sensitivity::{Sensitivity, TrustLevel};

    let home = tempfile::tempdir().unwrap();
    let engine = vault(&home.path().join("vault"));
    load(&engine, TrustLevel::FirstParty);

    // A people log: the user asserting they saw someone. Long enough to be an
    // exemplar candidate, so "it is not in the voice" is a real assertion
    // rather than one the length filter would satisfy on its own.
    let dek = engine.dek().expect("dek");
    let source = ghostr_core::ids::SourceId::new(9_999, [9u8; 10]);
    engine
        .store()
        .upsert_source_with(
            dek,
            &ghostr_store::sqlite::NewSourceRow {
                id: source,
                kind_tag: "structured_log",
                config: "{\"location\":\"/health\"}",
                trust: TrustLevel::SelfReported,
                sensitivity: Sensitivity::Private,
            },
            [7u8; 24],
        )
        .expect("source");

    let logged = logged_memory(source);
    engine
        .store()
        .put_memory(dek, &logged, engine.nonce())
        .expect("put");
    seal_all(&engine);

    let model = ops::propose_persona(&engine).expect("propose").model;

    // It fed the distillation: `derived_from` is what the model admits reading.
    assert!(
        model.derived_from.contains(&logged.id),
        "a self-reported memory must be able to feed the model"
    );
    // And it is not in the ghost's mouth.
    assert!(
        !model.facets.voice.exemplars.contains(&logged.id),
        "a self-reported memory became a voice exemplar"
    );
}

/// A row a structured log would produce, long enough to rank as an exemplar.
fn logged_memory(source: ghostr_core::ids::SourceId) -> ghostr_core::memory::Memory {
    use ghostr_core::memory::{Memory, MemoryBody, MemoryKind, Provenance};

    let text = "Saw Nan at the clinic on Tuesday morning again, third week running now";
    Memory {
        id: ghostr_core::ids::MemoryId::new(1_767_000_000_000, [3u8; 10]),
        source_id: source,
        occurred_at: Some(Timestamp::new(1_767_000_000_000, 0)),
        ingested_at: Timestamp::new(1_767_000_000_000, 0),
        kind: MemoryKind::Relationship,
        body: MemoryBody {
            text: text.to_owned(),
            structured: None,
            redactions: Vec::new(),
        },
        entities: Vec::new(),
        salience: 0.4,
        sensitivity: ghostr_core::sensitivity::Sensitivity::Private,
        provenance: Provenance {
            source_id: source,
            external_id: Some("health.jsonl:1".to_owned()),
            url: None,
            raw_hash: ghostr_core::hash::tagged_hash(
                ghostr_core::hash::Tag::MemoryLeaf,
                b"health.jsonl:1",
            ),
        },
        salt: [5u8; 32],
        supersedes: None,
        embedding: None,
    }
}

/// THREAT_MODEL §T7. A feed is not the user's voice, so its content never
/// becomes an exemplar the ghost speaks from — and with nothing else in the
/// vault there is not enough first-party corpus to distil at all.
#[test]
fn third_party_content_is_not_eligible_to_build_a_voice() {
    let home = tempfile::tempdir().unwrap();
    let engine = vault(&home.path().join("vault"));
    load(&engine, TrustLevel::ThirdParty);
    seal_all(&engine);

    let err = ops::propose_persona(&engine).expect_err("must refuse");
    assert!(
        matches!(
            err,
            ghostr_engine::Error::Persona(ghostr_persona::Error::InsufficientCorpus {
                have: 0,
                ..
            })
        ),
        "got {err:?}"
    );
}

/// A ghost built from four notes would be confident and wrong. This is a real
/// state for a new user, not a failure.
#[test]
fn a_new_vault_has_too_little_corpus_to_distil() {
    let home = tempfile::tempdir().unwrap();
    let engine = vault(&home.path().join("vault"));
    let err = ops::propose_persona(&engine).expect_err("must refuse");
    assert!(matches!(
        err,
        ghostr_engine::Error::Persona(ghostr_persona::Error::InsufficientCorpus { .. })
    ));
}

/// SPEC §6.4. A quest issued under v1 is scored against v1's claim, so old
/// versions survive a new head.
#[test]
fn adopting_a_second_version_keeps_the_first() {
    let home = tempfile::tempdir().unwrap();
    let engine = vault(&home.path().join("vault"));
    let memories = load(&engine, TrustLevel::FirstParty);
    seal_all(&engine);

    let first = ops::propose_persona(&engine).expect("v1");
    ops::adopt_persona(&engine, &first).expect("adopt v1");

    // Change the corpus so the second version genuinely differs.
    let dek = engine.dek().expect("dek");
    let mut extra = memories[0].clone();
    extra.id = ghostr_core::ids::MemoryId::new(9_999, [9u8; 10]);
    extra.body.text = "Therefore, moreover, regarding the matter: however, furthermore, \
                       accordingly the schedule shall proceed as previously stated herein."
        .to_owned();
    extra.provenance.raw_hash =
        ghostr_core::hash::tagged_hash(ghostr_core::hash::Tag::MemoryLeaf, b"extra");
    engine
        .store()
        .put_memory(dek, &extra, engine.nonce())
        .expect("put");

    let second = ops::propose_persona(&engine).expect("v2");
    assert_eq!(second.model.version.ordinal, 2);
    assert_eq!(second.replaces, Some(first.model.version));
    ops::adopt_persona(&engine, &second).expect("adopt v2");

    // Both are readable, and the diff between them works.
    let history = ops::persona_history(&engine, 10).expect("history");
    assert_eq!(history.len(), 2);
    assert!(history[0].is_head);
    assert!(!history[1].is_head);

    let diff = ops::persona_diff(&engine, 1, 2).expect("diff");
    assert_eq!(diff.from, first.model.version);
    assert_eq!(diff.to, second.model.version);
}

#[test]
fn diffing_an_absent_version_says_so() {
    let home = tempfile::tempdir().unwrap();
    let engine = vault(&home.path().join("vault"));
    let err = ops::persona_diff(&engine, 1, 2).expect_err("must fail");
    assert!(format!("{err}").contains("no persona version"));
}
