//! The M0 operations: ingest, memoria, anchor, verify.
//!
//! Each is a free function over an [`Engine`], because they are workflows rather
//! than state. The engine holds the wiring; these hold the order things happen
//! in.

use chrono::{NaiveDate, NaiveTime};
use ghostr_anchor::{AnchorState, OtsClient};
use ghostr_core::footage::{Amendment, AmendmentReason, Commitment, Footage, Thread};
use ghostr_core::hash::Hash32;
use ghostr_core::ids::{EntityId, MemoryId, PersonaVersion, SourceId, ThreadId};
use ghostr_core::memory::Memory;
use ghostr_core::persona::PersonaModel;
use ghostr_core::time::Timestamp;
use ghostr_ingest::markdown;
use ghostr_memoria::compose::{self, NoteExtraction};
use ghostr_memoria::extract;
use ghostr_memoria::pipeline::DraftFootage;
use ghostr_memoria::summarize::{NaiveSummarizer, Summarizer};
pub use ghostr_persona::CandidateVersion;
use ghostr_store::memory::TimeRange;
use ghostr_store::sqlite::{AnchorRecord, AnchorRecordState};

use crate::engine::Engine;

/// At most this many highlights per day, so a recap stays readable.
const MAX_HIGHLIGHTS: usize = 8;

/// What one `ingest` run did.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct IngestReport {
    /// Files that produced a new memory.
    pub ingested: u32,
    /// Files already present, skipped by content digest.
    pub skipped: u32,
    /// Files that could not be read or parsed.
    pub failed: u32,
}

/// Ingests every markdown file under `path`.
///
/// Idempotent: re-running over an unchanged vault ingests nothing, because the
/// store's unique index on `(source_id, raw_hash)` rejects the duplicate and
/// this counts it as skipped rather than failing.
///
/// # Errors
///
/// Returns [`Error::Ingest`](crate::Error::Ingest) if the directory cannot be
/// read.
pub fn ingest(engine: &Engine, path: &std::path::Path) -> crate::Result<IngestReport> {
    let dek = engine.dek()?;
    let now = engine.now();

    let mut source_random = [0u8; 10];
    engine.rng().fill(&mut source_random);
    let source_id = engine.store().upsert_source(
        dek,
        SourceId::new(now.utc_millis().unsigned_abs(), source_random),
        markdown::KIND_TAG,
        &path.display().to_string(),
        engine.nonce(),
    )?;

    let notes = markdown::scan_vault(path, source_id)?;
    let mut report = IngestReport::default();

    for note in &notes {
        let memory = markdown::to_memory(note, source_id, engine.clock(), engine.rng());
        if engine
            .store()
            .has_raw_hash(source_id, memory.provenance.raw_hash)?
        {
            report.skipped += 1;
            continue;
        }
        match engine.store().put_memory(dek, &memory, engine.nonce()) {
            Ok(()) => report.ingested += 1,
            // A racing duplicate lands here. Counted as skipped, not failed:
            // the outcome the user cares about is that the note is stored once.
            Err(ghostr_store::Error::AppendOnlyViolation { .. }) => report.skipped += 1,
            Err(e) => return Err(e.into()),
        }
    }
    Ok(report)
}

/// Compiles and seals one day's footage.
///
/// The whole Memoria pipeline for M0: window, extract deterministically,
/// compose, validate, seal. Sealing is the point of no return — after it the
/// footage is immutable and the chain has advanced.
///
/// # Errors
///
/// Returns [`Error::Memoria`](crate::Error::Memoria) if the day is already
/// sealed, or [`Error::Store`](crate::Error::Store) if the seal would fork or
/// gap the chain.
pub fn memoria(engine: &Engine, date: NaiveDate) -> crate::Result<MemoriaOutcome> {
    let tz = engine.home_tz()?;

    if let Some(existing) = engine.store().date_is_sealed(date)? {
        return Err(crate::Error::Memoria(
            ghostr_memoria::Error::AlreadySealed { seq: existing },
        ));
    }

    // The window runs from the previous cutoff to this day's. Both ends are
    // absolute instants, so a timezone change mid-window cannot double-count or
    // drop a note (SPEC Q11).
    let window = day_window(date, &tz);

    let dek = engine.dek()?;
    let memories = engine.store().window(dek, window)?;

    let summarizer = NaiveSummarizer;
    let notes: Vec<NoteExtraction<'_>> = memories
        .iter()
        .map(|m| NoteExtraction {
            memory: m,
            extraction: extract::extract(&m.body.text),
        })
        .collect();

    let highlights = compose::highlights(&notes, &summarizer, MAX_HIGHLIGHTS);
    let mood = compose::mood(&notes);
    let unresolved = compose::unresolved(&notes);

    // M0 has no entity store wiring yet, so a person's id is derived
    // deterministically from their name. That keeps the same @mention resolving
    // to the same id across days without inventing a resolution step the
    // milestone does not need.
    // The real entity table, not a hash of the name: an entity that exists as a
    // row is one the redactor can pseudonymise at the egress boundary, and one
    // the user can see and merge. A derived id is neither.
    let people = compose::people(&notes, &|name| resolve_person(engine, name));

    let previous_open = carry_forward_threads(engine)?;
    let seq = engine.store().tip()?.map_or(1, |t| t.seq + 1);
    let thread_update = compose::threads(&previous_open, &notes, seq, &|| {
        let mut random = [0u8; 10];
        engine.rng().fill(&mut random);
        ThreadId::new(engine.now().utc_millis().unsigned_abs(), random)
    });

    // A memory that arrived after its own day sealed does not go back into it.
    // It lands here, as an amendment pointing at the day it missed (I2).
    let amendments = late_arrival_amendments(engine, &summarizer)?;

    let mut draft = DraftFootage {
        seq,
        date,
        tz,
        window,
        // An empty day still seals and still advances seq. A gap in the chain is
        // indistinguishable from a deletion, so there are no gaps (SPEC I3).
        empty: memories.is_empty(),
        highlights,
        people,
        mood,
        open_threads: thread_update.open,
        closed_loops: thread_update.closed,
        // The previous day's carry *plus* whatever today opened. A task
        // written down and ticked off the same day closes a thread that was
        // never carried in, and without it here the day refuses to seal at all.
        carried_threads: previous_open
            .iter()
            .map(|t| t.id)
            .chain(thread_update.opened.iter().copied())
            .collect(),
        unresolved,
        memory_ids: memories.iter().map(|m| m.id).collect(),
        amendments,
        persona_version: PersonaVersion::genesis(),
    };

    // Drop first, then validate. Dropping is the filter — an unsupported claim
    // is removed rather than allowed to stop the day closing — and validation
    // is the backstop that catches anything dropping could not fix (SPEC §6).
    let dropped_claims = ghostr_memoria::drop_unevidenced(&mut draft);
    if let Err(errors) = ghostr_memoria::validate_draft(&draft) {
        return Err(crate::Error::Memoria(
            ghostr_memoria::Error::ValidationFailed {
                count: errors.len(),
                broken: errors.iter().map(|e| format!("{e:?}")).collect(),
            },
        ));
    }
    // Everything the quest loop has produced since the last cutoff. Selected by
    // "not yet committed" rather than by a date window: a verdict recorded after
    // a day sealed but timestamped inside it would otherwise join that day's
    // leaves retroactively, and a root that changes after sealing is one nobody
    // can recompute (I2, I3).
    let issued = engine.store().quests_awaiting_commitment(dek)?;
    let answered = engine.store().verdicts_awaiting_commitment(dek)?;
    let (root, leaves, leaf_count) = build_root(
        &memories,
        &QuestActivity {
            issued: &issued,
            answered: &answered,
        },
        ghostr_core::footage::CommitmentVersion::current(),
        seq,
        date,
        &tz,
    )?;
    let prev_link = match engine.store().tip()? {
        Some(tip) => tip.link,
        None => engine.store().genesis_link()?,
    };
    let link = ghostr_anchor::link(prev_link, root, seq, date, &tz);

    let footage = Footage {
        seq: draft.seq,
        date: draft.date,
        tz: draft.tz,
        window: (draft.window.start, draft.window.end),
        empty: draft.empty,
        highlights: draft.highlights,
        people: draft.people,
        mood: draft.mood,
        open_threads: draft.open_threads,
        closed_loops: draft.closed_loops,
        unresolved: draft.unresolved,
        memory_ids: draft.memory_ids,
        amendments: draft.amendments,
        persona_version: draft.persona_version,
        commitment: Commitment {
            merkle_root: root,
            prev_link,
            link,
            leaf_count,
            version: ghostr_core::footage::CommitmentVersion::current(),
        },
        sealed_at: engine.now(),
    };

    let nonce = engine.nonce();
    engine.store().seal_footage(dek, &footage, &leaves, nonce)?;
    // Stamped only after the seal succeeded. The other order would mark quests
    // as committed to a day that then failed to seal, and nothing would ever
    // commit to them again.
    engine.store().mark_committed(
        seq,
        &issued.iter().map(|q| q.id).collect::<Vec<_>>(),
        &answered.iter().map(|(q, _)| q.id).collect::<Vec<_>>(),
    )?;
    Ok(MemoriaOutcome {
        footage,
        dropped_claims,
    })
}

/// What one `memoria` run produced.
#[derive(Debug, Clone, PartialEq)]
pub struct MemoriaOutcome {
    /// The sealed day.
    pub footage: Footage,
    /// Claims removed for want of evidence.
    ///
    /// Reported rather than swallowed. A recap that quietly got shorter is a
    /// recap the user cannot tell from one that had less to say.
    pub dropped_claims: usize,
}

/// Builds the day's Merkle root and the per-memory leaves.
/// A quest and when its verdict was given.
type AnsweredQuest = (ghostr_core::quest::Quest, Timestamp);

/// A day's root, the memory leaves it can prove inclusion against, and how many
/// leaves went into it.
type SealedRoot = (Hash32, Vec<(MemoryId, Hash32)>, u32);

/// The day's quest activity, as it goes into the tree.
struct QuestActivity<'a> {
    /// Quests this day is committing to.
    issued: &'a [ghostr_core::quest::Quest],
    /// Verdicts this day is committing to, whichever day asked.
    answered: &'a [AnsweredQuest],
}

/// Builds the day's Merkle root.
///
/// The leaf set depends on the version being sealed under, and that is the
/// whole point: a day sealed before quests reached the tree must keep
/// verifying, because its root is already in Bitcoin and cannot be recomputed
/// (CLAUDE.md §4.7).
///
/// `meta_leaf` is deliberately untouched by this change. It counts memories and
/// nothing else, so a day with no quests produces a byte-identical root under
/// either version — which is why the two versions agree on every day that
/// predates the feature, and disagree only where there is something new to
/// commit to.
fn build_root(
    memories: &[Memory],
    quests: &QuestActivity<'_>,
    version: ghostr_core::footage::CommitmentVersion,
    seq: u64,
    date: NaiveDate,
    tz: &chrono_tz::Tz,
) -> crate::Result<SealedRoot> {
    use ghostr_core::footage::CommitmentVersion;

    let mut leaves = Vec::with_capacity(memories.len());
    let mut digests = Vec::with_capacity(memories.len() + 1);

    // Every day has a metadata leaf, which is why an empty day still has a
    // non-empty tree and can therefore seal.
    digests.push(ghostr_anchor::meta_leaf(
        seq,
        date,
        tz,
        u32::try_from(memories.len()).unwrap_or(u32::MAX),
    ));

    for memory in memories {
        let canonical = ghostr_core::canonical::to_canonical_cbor(&LeafPayload {
            id: memory.id,
            text: &memory.body.text,
            occurred_at: memory.occurred_at.map(|t| t.utc_millis()),
        })?;
        let leaf = ghostr_anchor::memory_leaf(&memory.salt, &canonical);
        leaves.push((memory.id, leaf));
        digests.push(leaf);
    }

    if version >= CommitmentVersion::WithQuests {
        for quest in quests.issued {
            digests.push(ghostr_anchor::quest_leaf(
                &quest.nonce,
                &ghostr_core::canonical::to_canonical_cbor(&quest_payload(quest)?)?,
            ));
        }
        for (quest, answered_at) in quests.answered {
            let Some(verdict) = &quest.verdict else {
                continue;
            };
            digests.push(ghostr_anchor::verdict_leaf(
                &quest.nonce,
                &ghostr_core::canonical::to_canonical_cbor(&VerdictLeafPayload {
                    quest_id: quest.id,
                    verdict: verdict_tag(verdict),
                    severity: severity_tag(verdict),
                    answered_at: answered_at.utc_millis(),
                })?,
            ));
        }
    }

    // Counted here rather than derived by the caller: the caller no longer
    // knows how many leaves there are, and a `leaf_count` that disagreed with
    // the tree would produce inclusion proofs of the wrong shape.
    let count = u32::try_from(digests.len()).unwrap_or(u32::MAX);
    Ok((ghostr_anchor::root(digests)?, leaves, count))
}

/// Re-derives a sealed day's quest and verdict leaves.
///
/// Reads the same rows the seal read, in the same order. If a quest was edited,
/// deleted, or added after the fact, the digests differ and the root stops
/// matching — which is the whole point of putting them in the tree.
fn quest_digests(engine: &Engine, footage: &Footage) -> crate::Result<Vec<Hash32>> {
    let dek = engine.dek()?;
    let mut out = Vec::new();

    for quest in engine.store().quests_committed_at(dek, footage.seq)? {
        out.push(ghostr_anchor::quest_leaf(
            &quest.nonce,
            &ghostr_core::canonical::to_canonical_cbor(&quest_payload(&quest)?)?,
        ));
    }
    for (quest, answered_at) in engine.store().verdicts_committed_at(dek, footage.seq)? {
        let Some(verdict) = &quest.verdict else {
            continue;
        };
        out.push(ghostr_anchor::verdict_leaf(
            &quest.nonce,
            &ghostr_core::canonical::to_canonical_cbor(&VerdictLeafPayload {
                quest_id: quest.id,
                verdict: verdict_tag(verdict),
                severity: severity_tag(verdict),
                answered_at: answered_at.utc_millis(),
            })?,
        ));
    }
    Ok(out)
}

/// The canonical form of a quest, as issued.
fn quest_payload(quest: &ghostr_core::quest::Quest) -> crate::Result<QuestLeafPayload> {
    use ghostr_core::canonical::ratio_to_fixed;

    Ok(QuestLeafPayload {
        id: quest.id,
        issued_for: quest.issued_for.to_string(),
        persona_ordinal: quest.persona_version.ordinal,
        persona_content: quest.persona_version.content.to_hex(),
        kind: quest.kind.variant_name(),
        facet: format!("{:?}", quest.facet),
        difficulty: ratio_to_fixed(quest.difficulty, "difficulty")?,
        confidence: ratio_to_fixed(quest.confidence, "confidence")?,
        answer_commitment: quest.answer_commitment.to_hex(),
        holdout: quest.holdout,
        decoy: quest.decoy,
    })
}

/// How far off a correction was, for a preimage.
const fn severity_tag(verdict: &ghostr_core::quest::Verdict) -> Option<&'static str> {
    use ghostr_core::quest::{Severity, Verdict};

    match verdict {
        Verdict::Correct { severity, .. } => Some(match severity {
            Severity::Minor => "minor",
            Severity::Major => "major",
        }),
        _ => None,
    }
}

/// What a quest leaf commits to: the quest **as issued**.
///
/// # Why the claim itself is not in here
///
/// A leaf may be revealed to a third party to prove inclusion, and its preimage
/// is revealed with it. Putting the claim in would mean proving "a quest existed
/// on this day" could not be done without disclosing what it asked — and quests
/// are about the user's own life.
///
/// The commitment covers it anyway, transitively:
/// [`verify_commitment`](ghostr_quests::verify_commitment) proves a claim
/// reproduces `answer_commitment`, and this leaf proves `answer_commitment` was
/// in the day's root. Two steps, each already implemented, and the second one
/// discloses nothing.
///
/// # Why the verdict is not in here either
///
/// It has not happened yet. A quest stays answerable for 48 hours, so its
/// verdict usually lands after its day has sealed — and a sealed footage is
/// immutable (I2). The verdict gets its own leaf, in the day it was given.
///
/// Fixed point rather than floats, because canonical CBOR rejects floats: one
/// value must have exactly one encoding (SPEC §7.1).
#[derive(serde::Serialize)]
struct QuestLeafPayload {
    id: ghostr_core::ids::QuestId,
    issued_for: String,
    persona_ordinal: u32,
    persona_content: String,
    kind: &'static str,
    facet: String,
    difficulty: u32,
    confidence: u32,
    answer_commitment: String,
    holdout: bool,
    decoy: bool,
}

/// What a verdict leaf commits to.
///
/// The shape of the answer, not its words. A correction's text became a memory
/// on this same day, so it is already a leaf in this same tree — committing it
/// twice would buy nothing and would put the user's own sentence into a preimage
/// that gets revealed to prove a verdict happened.
#[derive(serde::Serialize)]
struct VerdictLeafPayload {
    quest_id: ghostr_core::ids::QuestId,
    verdict: &'static str,
    severity: Option<&'static str>,
    answered_at: i64,
}

/// The stable name of a verdict, for a preimage.
///
/// Hand-written rather than derived: a `Debug` rendering is a formatting
/// decision, and one of those changing would silently fork every chain sealed
/// after it.
const fn verdict_tag(verdict: &ghostr_core::quest::Verdict) -> &'static str {
    use ghostr_core::quest::Verdict;

    match verdict {
        Verdict::Confirm => "confirm",
        Verdict::Correct { .. } => "correct",
        Verdict::Reject { .. } => "reject",
        Verdict::Unknown => "unknown",
        Verdict::Void { .. } => "void",
        _ => "unrecognised",
    }
}

/// What a memory leaf commits to.
///
/// Deliberately narrow: id, content, and occurrence time. Ingest metadata
/// (`ingested_at`, salience) is excluded because it can legitimately differ
/// between two devices ingesting the same note, and a commitment that depends
/// on it would make the same memory hash two ways.
#[derive(serde::Serialize)]
struct LeafPayload<'a> {
    id: MemoryId,
    text: &'a str,
    occurred_at: Option<i64>,
}

/// Resolves a name to an entity in the store, creating one if it is unknown.
///
/// Falls back to [`entity_id_for`] if the store cannot be reached. That keeps a
/// day sealable when entity resolution fails, at the cost of an id with no row
/// behind it — which the redactor cannot pseudonymise. The fallback is the
/// lesser harm only because the alternative is a gap in the chain (I3); it is
/// not a good outcome and it is why `resolve_entity` is worth keeping cheap.
fn resolve_person(engine: &Engine, name: &str) -> EntityId {
    let Ok(dek) = engine.dek() else {
        return entity_id_for(name);
    };
    let mut random = [0u8; 10];
    engine.rng().fill(&mut random);
    let now = engine.now();
    engine
        .store()
        .resolve_entity(
            dek,
            name,
            ghostr_store::entity::EntityKind::Person,
            now,
            EntityId::new(now.utc_millis().unsigned_abs(), random),
            engine.nonce(),
        )
        .map_or_else(|_| entity_id_for(name), |stored| stored.id)
}

/// A deterministic entity id for a name.
///
/// Same name, same id, forever — without an entity table. The fallback when the
/// store cannot resolve one.
fn entity_id_for(name: &str) -> EntityId {
    let digest = ghostr_core::hash::tagged_hash(
        ghostr_core::hash::Tag::MetaLeaf,
        format!("entity:{}", name.to_lowercase()).as_bytes(),
    );
    let mut random = [0u8; 10];
    random.copy_from_slice(&digest.as_bytes()[..10]);
    // The timestamp half comes from the digest too, so the *whole* id varies by
    // name rather than only its tail.
    let millis = u64::from_be_bytes([
        0,
        0,
        digest.as_bytes()[10],
        digest.as_bytes()[11],
        digest.as_bytes()[12],
        digest.as_bytes()[13],
        digest.as_bytes()[14],
        digest.as_bytes()[15],
    ]);
    EntityId::new(millis, random)
}

/// How long an amendment's note may be.
const AMENDMENT_CHARS: usize = 160;

/// Amendments for every memory that arrived after its own day had sealed.
///
/// This is the whole of I2 in practice. A nostr note from three days ago, pulled
/// in today, does not retroactively enter a sealed window — that window's
/// commitment is fixed and re-deriving it with an extra leaf would break every
/// link after it. The memory lands in *today's* footage instead, with an
/// amendment naming the day it should have been in.
///
/// A memory whose time predates the first sealed day amends nothing: there is no
/// day for it to correct. It still enters today's window as an ordinary memory.
fn late_arrival_amendments(
    engine: &Engine,
    summarizer: &dyn Summarizer,
) -> crate::Result<Vec<Amendment>> {
    let Some(tip) = engine.store().tip()? else {
        // Nothing sealed yet, so nothing can be late.
        return Ok(Vec::new());
    };
    let dek = engine.dek()?;
    let Some(last) = engine.store().get_footage(dek, tip.seq)? else {
        return Ok(Vec::new());
    };
    let sealed_through = last.window.1;

    let late = engine
        .store()
        .late_arrivals(dek, sealed_through, tip.sealed_at)?;

    let mut out = Vec::new();
    for memory in &late {
        let at = memory.occurred_at.unwrap_or(memory.ingested_at);
        let Some(target_seq) = engine.store().sealed_seq_covering(at)? else {
            continue;
        };
        out.push(Amendment {
            target_seq,
            reason: AmendmentReason::LateArrival,
            note: summarizer.summarize(&memory.body.text, AMENDMENT_CHARS),
            memory_ids: vec![memory.id],
        });
    }
    // Grouped by the day they correct, then by memory, so the list is stable —
    // it is hashed into today's root.
    out.sort_by(|a, b| {
        a.target_seq
            .cmp(&b.target_seq)
            .then_with(|| a.memory_ids.cmp(&b.memory_ids))
    });
    Ok(out)
}

/// The threads left open by the most recent sealed day.
fn carry_forward_threads(engine: &Engine) -> crate::Result<Vec<Thread>> {
    let Some(tip) = engine.store().tip()? else {
        return Ok(Vec::new());
    };
    let dek = engine.dek()?;
    Ok(engine
        .store()
        .get_footage(dek, tip.seq)?
        .map(|f| f.open_threads)
        .unwrap_or_default())
}

/// The half-open absolute window for one local calendar day.
fn day_window(date: NaiveDate, tz: &chrono_tz::Tz) -> TimeRange {
    use chrono::TimeZone as _;

    let start_local = date.and_time(NaiveTime::MIN);
    let end_local = date.succ_opt().unwrap_or(date).and_time(NaiveTime::MIN);

    // `from_local_datetime` is ambiguous across a DST fold and absent across a
    // spring-forward gap. Taking the earliest candidate makes the choice
    // deterministic in both cases rather than depending on which branch a
    // library happens to return.
    let start = tz
        .from_local_datetime(&start_local)
        .earliest()
        .map_or(0, |dt| dt.timestamp_millis());
    let end = tz
        .from_local_datetime(&end_local)
        .earliest()
        .map_or(0, |dt| dt.timestamp_millis());

    TimeRange {
        start: Timestamp::new(start, 0),
        end: Timestamp::new(end, 0),
    }
}

/// Submits the chain tip to OpenTimestamps calendars.
///
/// The only command that touches the network. Being offline yields
/// [`AnchorState::Failed`], not an error: the chain is already valid without an
/// attestation.
///
/// # Errors
///
/// Returns [`Error::Config`](crate::Error::Config) if there is nothing sealed to
/// anchor yet.
pub fn anchor(engine: &Engine, client: &OtsClient) -> crate::Result<AnchorRecord> {
    let Some(tip) = engine.store().tip()? else {
        return Err(crate::Error::Config {
            detail: "nothing sealed yet — run `ghostr memoria` first".to_owned(),
        });
    };

    let submission = client.submit(tip.link, engine.now())?;
    let ots = submission
        .ots_bytes
        .as_ref()
        .and_then(|body| ghostr_anchor::ots::to_detached_file(tip.link, body).ok());

    // Persist the proof beside the store so it survives independently of the
    // database — a `.ots` file is a complete proof on its own and should not
    // need the vault to be readable.
    if let Some(bytes) = &ots {
        let dir = engine.dir().join("anchors");
        if std::fs::create_dir_all(&dir).is_ok() {
            let _ = std::fs::write(dir.join(format!("{}.ots", tip.seq)), bytes);
        }
    }

    let record = AnchorRecord {
        seq: tip.seq,
        state: match &submission.state {
            AnchorState::Pending { .. } => AnchorRecordState::Pending,
            AnchorState::Confirmed { .. } => AnchorRecordState::Confirmed,
            AnchorState::Failed { .. } => AnchorRecordState::Failed,
            // AnchorState is #[non_exhaustive]; anything unrecognised means the
            // digest is not attested, which is the safe reading.
            _ => AnchorRecordState::Unanchored,
        },
        digest: tip.link,
        submitted_at: Some(engine.now()),
        block_height: None,
        attempts: match &submission.state {
            AnchorState::Failed { attempts, .. } => *attempts,
            _ => 1,
        },
        detail: match &submission.state {
            AnchorState::Failed { last_error, .. } => Some(last_error.clone()),
            AnchorState::Pending { calendars, .. } => Some(calendars.join(", ")),
            _ => None,
        },
        ots,
    };
    engine.store().put_anchor(&record)?;
    Ok(record)
}

/// The result of verifying a chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyReport {
    /// How many days were checked.
    pub days: u64,
    /// Whether every link recomputed.
    pub chain_ok: bool,
    /// Whether every stored Merkle root matched its leaves.
    pub roots_ok: bool,
    /// The first bad sequence, when something failed.
    pub first_bad_seq: Option<u64>,
    /// What went wrong, in a sentence.
    pub detail: Option<String>,
    /// How many days carry an OpenTimestamps proof.
    pub anchored: u64,
    /// How many days are still awaiting confirmation.
    pub pending: u64,
}

/// Verifies the chain from genesis.
///
/// Two independent checks. Links must recompute from their parents — that is
/// what makes the history append-only. And each stored Merkle root must match
/// the leaves the store still holds, which catches a memory altered *after*
/// sealing even though the link itself would still verify.
///
/// # Errors
///
/// Returns [`Error::Store`](crate::Error::Store) if the store cannot be read.
pub fn verify(engine: &Engine) -> crate::Result<VerifyReport> {
    let dek = engine.dek()?;
    let genesis_link = engine.store().genesis_link()?;
    let footage = engine.store().all_footage(dek)?;

    let records: Vec<ghostr_anchor::ChainRecord> = footage
        .iter()
        .map(|f| ghostr_anchor::ChainRecord {
            seq: f.seq,
            date: f.date,
            tz: f.tz,
            root: f.commitment.merkle_root,
            prev_link: f.commitment.prev_link,
            link: f.commitment.link,
        })
        .collect();

    let mut report = VerifyReport {
        days: footage.len() as u64,
        chain_ok: true,
        roots_ok: true,
        first_bad_seq: None,
        detail: None,
        anchored: 0,
        pending: 0,
    };

    if let Err(e) = ghostr_anchor::verify_run(genesis_link, &records) {
        report.chain_ok = false;
        report.first_bad_seq = match &e {
            ghostr_anchor::Error::ChainBroken { seq } => Some(*seq),
            ghostr_anchor::Error::ChainGap { next, .. } => Some(*next),
            _ => None,
        };
        report.detail = Some(e.to_string());
        // Stop here: every link after a break also fails, and recomputing roots
        // past the break would bury the sequence that actually matters.
        return Ok(report);
    }

    for f in &footage {
        let stored = engine.store().footage_leaves(f.seq)?;
        let mut digests = vec![ghostr_anchor::meta_leaf(
            f.seq,
            f.date,
            &f.tz,
            u32::try_from(stored.len()).unwrap_or(u32::MAX),
        )];
        digests.extend(stored.iter().map(|(_, leaf)| *leaf));

        // Each day is re-derived under the rules it was *sealed* under, not the
        // rules this build prefers. A day sealed before quests reached the tree
        // has none in its root, and its root is already in Bitcoin — recomputing
        // it with today's leaf set would report tampering where there is none
        // (CLAUDE.md §4.7).
        if f.commitment.version >= ghostr_core::footage::CommitmentVersion::WithQuests {
            digests.extend(quest_digests(engine, f)?);
        }

        match ghostr_anchor::root(digests) {
            Ok(root) if root == f.commitment.merkle_root => {}
            _ => {
                report.roots_ok = false;
                report.first_bad_seq = Some(f.seq);
                report.detail = Some(format!(
                    "merkle root for seq {} does not match its stored leaves",
                    f.seq
                ));
                return Ok(report);
            }
        }

        match engine.store().get_anchor(f.seq)? {
            Some(a) if a.state == AnchorRecordState::Confirmed => report.anchored += 1,
            Some(a) if a.state == AnchorRecordState::Pending => report.pending += 1,
            _ => {}
        }
    }

    Ok(report)
}

/// Records a journal entry.
///
/// Goes straight into the encrypted store. Ghostr never writes a plaintext
/// journal file, not even its own (I1) — which is why the journal source has no
/// location and nothing to poll.
///
/// # Errors
///
/// Returns [`Error::Config`](crate::Error::Config) if the entry is empty, or
/// [`Error::Store`](crate::Error::Store) if the write fails.
pub fn journal_add(engine: &Engine, text: &str) -> crate::Result<MemoryId> {
    let text = text.trim();
    if text.is_empty() {
        return Err(crate::Error::Config {
            detail: "an empty journal entry records nothing".to_owned(),
        });
    }
    let dek = engine.dek()?;
    let source = journal_source(engine)?;
    let now = engine.now();
    let entry = ghostr_ingest::journal::JournalEntry {
        relative_path: String::new(),
        heading: now.utc_millis().to_string(),
        at: chrono::DateTime::from_timestamp_millis(now.utc_millis())
            .unwrap_or_default()
            .naive_utc(),
        text: text.to_owned(),
        basis: ghostr_ingest::adapter::TimeBasis::Stated,
    };
    let memory = ghostr_ingest::journal::to_memory(&entry, source, engine.clock(), engine.rng());
    engine.store().put_memory(dek, &memory, engine.nonce())?;
    Ok(memory.id)
}

/// Imports a running journal file, splitting it at its timestamp headings.
///
/// Idempotent: an unchanged entry keeps its digest, so re-importing after
/// appending adds exactly the new entries.
///
/// # Errors
///
/// Returns [`Error::Ingest`](crate::Error::Ingest) if the file cannot be read.
pub fn journal_import(engine: &Engine, path: &std::path::Path) -> crate::Result<IngestReport> {
    let dek = engine.dek()?;
    let source = journal_source(engine)?;
    let entries = ghostr_ingest::journal::scan(path, source)?;

    let mut report = IngestReport::default();
    for entry in &entries {
        let memory = ghostr_ingest::journal::to_memory(entry, source, engine.clock(), engine.rng());
        if engine
            .store()
            .has_raw_hash(source, memory.provenance.raw_hash)?
        {
            report.skipped += 1;
            continue;
        }
        match engine.store().put_memory(dek, &memory, engine.nonce()) {
            Ok(()) => report.ingested += 1,
            Err(ghostr_store::Error::AppendOnlyViolation { .. }) => report.skipped += 1,
            Err(e) => return Err(e.into()),
        }
    }
    Ok(report)
}

/// The journal source, created on first use.
fn journal_source(engine: &Engine) -> crate::Result<SourceId> {
    let dek = engine.dek()?;
    let mut random = [0u8; 10];
    engine.rng().fill(&mut random);
    Ok(engine.store().upsert_source_with(
        dek,
        &ghostr_store::sqlite::NewSourceRow {
            id: SourceId::new(engine.now().utc_millis().unsigned_abs(), random),
            kind_tag: ghostr_ingest::journal::KIND_TAG,
            // No location: the entries are in the store, not in a file.
            config: r#"{"location":""}"#,
            trust: ghostr_ingest::journal::default_trust(),
            sensitivity: ghostr_core::sensitivity::Sensitivity::Private,
        },
        engine.nonce(),
    )?)
}

/// A day's recap: the sealed footage if there is one, a preview if not.
#[derive(Debug, Clone, PartialEq)]
pub struct Recap {
    /// The day.
    pub date: NaiveDate,
    /// The footage, sealed or drafted.
    pub footage: Footage,
    /// Whether it is sealed, or a preview of a day still open.
    pub sealed: bool,
}

/// Shows a day, sealing nothing.
///
/// A day already sealed is read back. A day still open is compiled and shown
/// *without* being sealed: previewing a recap must not advance the chain, or
/// looking at today would silently close it (I2, I3).
///
/// # Errors
///
/// Returns [`Error::Store`](crate::Error::Store) if the read fails.
pub fn recap(engine: &Engine, date: NaiveDate) -> crate::Result<Recap> {
    let dek = engine.dek()?;
    if let Some(seq) = engine.store().date_is_sealed(date)?
        && let Some(footage) = engine.store().get_footage(dek, seq)?
    {
        return Ok(Recap {
            date,
            footage,
            sealed: true,
        });
    }
    let footage = preview(engine, date)?;
    Ok(Recap {
        date,
        footage,
        sealed: false,
    })
}

/// Compiles a day without sealing it.
///
/// Shares the compose stage with [`memoria`] and stops before the commitment.
/// The commitment fields are zeroed rather than computed: a preview that
/// carried a real-looking link would be a footage that never entered the chain
/// and looked like it had.
fn preview(engine: &Engine, date: NaiveDate) -> crate::Result<Footage> {
    let tz = engine.home_tz()?;
    let window = day_window(date, &tz);
    let dek = engine.dek()?;
    let memories = engine.store().window(dek, window)?;

    let summarizer = NaiveSummarizer;
    let notes: Vec<NoteExtraction<'_>> = memories
        .iter()
        .map(|m| NoteExtraction {
            memory: m,
            extraction: extract::extract(&m.body.text),
        })
        .collect();

    let previous_open = carry_forward_threads(engine)?;
    let seq = engine.store().tip()?.map_or(1, |t| t.seq + 1);
    let thread_update = compose::threads(&previous_open, &notes, seq, &|| {
        let mut random = [0u8; 10];
        engine.rng().fill(&mut random);
        ThreadId::new(engine.now().utc_millis().unsigned_abs(), random)
    });

    Ok(Footage {
        seq,
        date,
        tz,
        window: (window.start, window.end),
        empty: memories.is_empty(),
        highlights: compose::highlights(&notes, &summarizer, MAX_HIGHLIGHTS),
        // A preview resolves entities too, so the ids it shows are the ids the
        // sealed day will carry.
        people: compose::people(&notes, &|name| resolve_person(engine, name)),
        mood: compose::mood(&notes),
        open_threads: thread_update.open,
        closed_loops: thread_update.closed,
        unresolved: compose::unresolved(&notes),
        memory_ids: memories.iter().map(|m| m.id).collect(),
        amendments: Vec::new(),
        persona_version: PersonaVersion::genesis(),
        // Zeroed on purpose: nothing here is committed to anything.
        commitment: Commitment {
            merkle_root: Hash32::from_bytes([0u8; 32]),
            prev_link: Hash32::from_bytes([0u8; 32]),
            link: Hash32::from_bytes([0u8; 32]),
            leaf_count: 0,
            version: ghostr_core::footage::CommitmentVersion::current(),
        },
        sealed_at: engine.now(),
    })
}

/// Every thread open at the chain tip, plus the day each was opened.
///
/// # Errors
///
/// Returns [`Error::Store`](crate::Error::Store) if the read fails.
pub fn open_threads(engine: &Engine) -> crate::Result<Vec<Thread>> {
    carry_forward_threads(engine)
}

/// The egress log, newest first.
///
/// Reads the audit record of everything that left the device. An empty log on a
/// vault that has never used a remote model is the expected answer, and the one
/// a user should be able to confirm for themselves (SPEC I5).
///
/// # Errors
///
/// Returns [`Error::Store`](crate::Error::Store) if the read fails.
pub fn egress_log(
    engine: &Engine,
    since: Timestamp,
) -> crate::Result<Vec<ghostr_store::sqlite::EgressRecord>> {
    let mut records = engine.store().egress_since(since)?;
    records.reverse();
    Ok(records)
}

/// What a remote summarisation of one day would send, without sending it.
///
/// Backs `ghostr memoria --dry-run --remote`. The payload and the decision come
/// from the same code path a real call takes, so this cannot drift from what
/// actually happens — a preview that showed something other than the truth would
/// be worse than no preview.
#[cfg(feature = "llm")]
#[derive(Debug, Clone)]
pub struct RemoteDryRun {
    /// The day that would be summarised.
    pub date: NaiveDate,
    /// Memories in the window.
    pub memories: usize,
    /// Memories the gate would never even consider, being `Secret`.
    ///
    /// Counted separately because they are the interesting number: they are the
    /// ones the user is trusting the system not to send.
    pub secret_withheld: usize,
    /// One entry per note that would be sent.
    pub notes: Vec<ghostr_llm::gate::DryRun>,
}

/// Shows what a remote model would receive for one day.
///
/// # Errors
///
/// Returns [`Error::Llm`](crate::Error::Llm) if the provider is not compiled in,
/// or [`Error::Store`](crate::Error::Store) if the window cannot be read.
#[cfg(feature = "llm")]
pub fn dry_run_remote(
    engine: &Engine,
    date: NaiveDate,
    config: ghostr_llm::gate::RemoteModelConfig,
) -> crate::Result<RemoteDryRun> {
    use ghostr_core::sensitivity::{Sensitivity, TrustLevel};
    use ghostr_llm::model::TaskKind;
    use ghostr_llm::prompt::{PromptBuilder, TokenBudget};

    let tz = engine.home_tz()?;
    let window = day_window(date, &tz);
    let dek = engine.dek()?;
    let memories = engine.store().window(dek, window)?;
    let gated = crate::model::remote_model(engine, config)?;

    let mut out = RemoteDryRun {
        date,
        memories: memories.len(),
        secret_withheld: 0,
        notes: Vec::new(),
    };

    for memory in &memories {
        // Counted, and not built into a prompt at all. `Secret` content is not
        // "denied at the gate" — it never reaches the gate, which is one fewer
        // place for it to go wrong (I5).
        if memory.sensitivity == Sensitivity::Secret {
            out.secret_withheld += 1;
            continue;
        }
        let request = PromptBuilder::new(TaskKind::Summarization, TokenBudget(4096))
            .corpus(std::slice::from_ref(memory), TrustLevel::FirstParty)
            .build()?;
        out.notes.push(gated.dry_run(&request)?);
    }
    Ok(out)
}

/// How many sealed days a distillation reads.
///
/// A season. Long enough that a routine is visible and a stance has repeated
/// evidence; short enough that the ghost tracks who the user is now rather than
/// who they were two years ago.
const DISTILL_WINDOW_DAYS: usize = 90;

/// Distils a persona version without adopting it.
///
/// Proposing and adopting are separate steps, so a user reads the diff before
/// the ghost starts speaking from a new model. A large change taking effect
/// silently is exactly what the symbolic model exists to prevent (SPEC §3.6).
///
/// # Errors
///
/// Returns [`Error::Persona`](crate::Error::Persona) if there is not enough
/// corpus, if a held-out correction reached the queue, or if a claim carries no
/// evidence.
pub fn propose_persona(engine: &Engine) -> crate::Result<CandidateVersion> {
    use ghostr_persona::{DeterministicBuilder, DistillInput};

    let dek = engine.dek()?;
    let head = engine.store().persona_head(dek)?;

    let mut footage = engine.store().all_footage(dek)?;
    footage.sort_by_key(|f| f.seq);
    let recent: Vec<_> = footage
        .iter()
        .rev()
        .take(DISTILL_WINDOW_DAYS)
        .rev()
        .cloned()
        .collect();

    // First-party only. Voice exemplars are drawn from this slice, and a feed
    // item becoming an exemplar is how a stranger's voice ends up in the
    // ghost's mouth (THREAT_MODEL §T7).
    let all = engine.store().all_memories(dek)?;
    let trusted = first_party_sources(engine)?;
    let first_party: Vec<&Memory> = all
        .iter()
        .filter(|m| trusted.contains(&m.source_id))
        .collect();

    // Read, not drained: a proposal the user never adopts must not consume the
    // corrections it was built from. `adopt_persona` clears the queue.
    let deltas = engine.store().peek_deltas(dek)?;

    let next_ordinal = head.as_ref().map_or(1, |h| h.version.ordinal + 1);
    ghostr_persona::propose(
        &DeterministicBuilder,
        head.as_ref(),
        DistillInput {
            footage: &recent,
            first_party: &first_party,
            deltas: &deltas,
            now: engine.now(),
            next_ordinal,
        },
    )
    .map_err(crate::Error::Persona)
}

/// Adopts a proposed version, making it head.
///
/// # Errors
///
/// Returns [`Error::Store`](crate::Error::Store) if the write fails.
pub fn adopt_persona(engine: &Engine, candidate: &CandidateVersion) -> crate::Result<()> {
    let dek = engine.dek()?;
    engine
        .store()
        .put_persona(dek, &candidate.model, engine.nonce())?;
    // Cleared only now. The corrections are already baked into the adopted
    // model, and leaving them queued would apply each of them a second time at
    // the next distillation.
    engine.store().drain_deltas(dek)?;
    Ok(())
}

/// The current persona, if one has been distilled.
///
/// # Errors
///
/// Returns [`Error::Store`](crate::Error::Store) if the read fails.
pub fn persona_head(engine: &Engine) -> crate::Result<Option<PersonaModel>> {
    Ok(engine.store().persona_head(engine.dek()?)?)
}

/// The diff between two stored versions.
///
/// # Errors
///
/// Returns [`Error::Config`](crate::Error::Config) if either version is absent.
pub fn persona_diff(
    engine: &Engine,
    from: u32,
    to: u32,
) -> crate::Result<ghostr_core::persona::PersonaDiff> {
    let dek = engine.dek()?;
    let missing = |ordinal: u32| crate::Error::Config {
        detail: format!("no persona version {ordinal}"),
    };
    let a = engine
        .store()
        .get_persona(dek, from)?
        .ok_or_else(|| missing(from))?;
    let b = engine
        .store()
        .get_persona(dek, to)?
        .ok_or_else(|| missing(to))?;
    Ok(ghostr_persona::diff::diff(&a, &b))
}

/// Every persona version, newest first.
///
/// # Errors
///
/// Returns [`Error::Store`](crate::Error::Store) if the read fails.
pub fn persona_history(
    engine: &Engine,
    limit: u32,
) -> crate::Result<Vec<ghostr_store::sqlite::PersonaSummary>> {
    Ok(engine.store().persona_history(limit)?)
}

/// The sources whose content counts as the user's own voice.
///
/// Read from the store rather than assumed: a markdown vault is first-party, a
/// health export is self-reported, and a feed is neither. Getting this wrong in
/// the permissive direction is a vulnerability, not a bug (THREAT_MODEL §T7).
fn first_party_sources(engine: &Engine) -> crate::Result<std::collections::BTreeSet<SourceId>> {
    use ghostr_core::sensitivity::TrustLevel;

    Ok(engine
        .store()
        .all_sources(engine.dek()?)?
        .into_iter()
        .filter(|s| s.trust == TrustLevel::FirstParty)
        // I7. Held-out corrections are first-party and are excluded anyway:
        // training on one would mean the ghost had seen the answer to a
        // question it is about to be scored on (SPEC Q18).
        .filter(|s| s.kind_tag != VERDICT_HOLDOUT_SOURCE_TAG)
        .map(|s| s.id)
        .collect())
}

/// How far back engagement and fidelity look by default.
const QUEST_WINDOW_DAYS: i64 = 30;

/// The source trainable verdict-derived memories are filed under.
///
/// Its own source, not the vault's. A correction is the user answering a
/// question the ghost asked, and folding that into "markdown vault" would make
/// the corpus unable to tell what the user wrote unprompted from what the ghost
/// prompted out of them (SPEC Q18).
const VERDICT_SOURCE_TAG: &str = "verdict";

/// The source held-out verdict-derived memories are filed under.
///
/// I7 has a second door, and this is what closes it. Held-out corrections
/// already produce no [`PersonaDelta`](ghostr_core::persona::PersonaDelta) —
/// but the correction is *also* a memory, and distillation reads memories. A
/// held-out correction in the general corpus would train the ghost on the
/// answer to a question it is about to be scored on, through the corpus rather
/// than through the queue.
///
/// The words are kept rather than dropped: they are the user's own, and a
/// separate source is a foreign key rather than a naming convention somebody
/// has to remember (SPEC Q18).
const VERDICT_HOLDOUT_SOURCE_TAG: &str = "verdict_holdout";

/// What one `quest issue` produced.
///
/// Ids and counts only. The claims are the ghost's committed answers, and a
/// summary that carried them would put the answer key wherever this is printed
/// or logged (I6, I8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuestIssue {
    /// The day these were issued for.
    pub date: NaiveDate,
    /// The quests issued.
    pub issued: Vec<ghostr_core::ids::QuestId>,
    /// Which ghost made the claims.
    pub persona_version: PersonaVersion,
    /// How many stale quests this run closed.
    pub expired: u64,
}

/// Issues a day's quests, committing to every answer before any can be shown.
///
/// The commitment is written to the store *before* this returns, so there is no
/// window in which a quest exists and its commitment does not (SPEC I6). The
/// store's trigger then makes it immutable.
///
/// Refuses a day that already has quests rather than adding more: two runs on
/// one day would let a user re-roll until the questions looked easy.
///
/// # Errors
///
/// Returns [`Error::Config`](crate::Error::Config) if no persona has been
/// adopted, or if the day already has quests.
pub fn issue_quests(engine: &Engine, date: NaiveDate) -> crate::Result<QuestIssue> {
    use ghostr_quests::generate::{HoldoutPolicy, QuestContext};
    use ghostr_quests::{DeterministicGenerator, QuestGenerator as _};

    let dek = engine.dek()?;
    let now = engine.now();

    let persona = engine
        .store()
        .persona_head(dek)?
        .ok_or_else(|| crate::Error::Config {
            detail: "no persona yet — run `ghostr persona propose` then `adopt`".to_owned(),
        })?;

    if engine.store().quests_issued_for(date)? > 0 {
        return Err(crate::Error::Config {
            detail: format!("{date} already has quests"),
        });
    }

    // Before generating, not after: a stale quest still counted as open would
    // depress the completion rate and shrink today's batch for a user who is
    // actually keeping up.
    let expired = engine.store().expire_quests(now)?;

    let exemplars = voice_exemplars(engine, &persona)?;
    // Questions already waiting on the user's screen. Asking one of them again
    // today would double the weight of whatever it probes and read, to a person
    // opening the app, as the ghost having forgotten.
    let avoid: Vec<String> = engine
        .store()
        .quests_with_status(dek, ghostr_core::quest::QuestStatus::Open, 200)?
        .iter()
        .map(|q| q.kind.committed_answer().to_owned())
        .collect();
    let ctx = QuestContext {
        persona: &persona,
        version: persona.version,
        date,
        now,
        rng: engine.rng(),
        // Without a model the generator is limited to the mechanical kinds
        // anyway, and saying so is more honest than claiming a tier the build
        // has no way to reach.
        tier: ghostr_quests::generate::CapabilityTier::Small,
        engagement: engagement(engine, now)?,
        holdout: HoldoutPolicy::default(),
        avoid: &avoid,
        voice_exemplars: &exemplars,
    };

    let generator = DeterministicGenerator;
    let quests = generator.generate(&ctx, generator.daily_count(&ctx))?;

    let mut issued = Vec::with_capacity(quests.len());
    for quest in &quests {
        engine.store().put_quest(dek, quest, engine.nonce())?;
        issued.push(quest.id);
    }

    Ok(QuestIssue {
        date,
        issued,
        persona_version: persona.version,
        expired,
    })
}

/// Quests awaiting a verdict, newest first.
///
/// # Errors
///
/// Returns [`Error::Store`](crate::Error::Store) if the read fails.
pub fn open_quests(engine: &Engine, limit: u32) -> crate::Result<Vec<ghostr_core::quest::Quest>> {
    let dek = engine.dek()?;
    engine.store().expire_quests(engine.now())?;
    Ok(engine
        .store()
        .quests_with_status(dek, ghostr_core::quest::QuestStatus::Open, limit)?)
}

/// One quest by id.
///
/// # Errors
///
/// Returns [`Error::Config`](crate::Error::Config) if there is no such quest.
pub fn get_quest(
    engine: &Engine,
    id: ghostr_core::ids::QuestId,
) -> crate::Result<ghostr_core::quest::Quest> {
    engine
        .store()
        .get_quest(engine.dek()?, id)?
        .ok_or_else(|| crate::Error::Config {
            detail: format!("no quest {}", id.display_short()),
        })
}

/// One quest by a full id or the short form `quest list` prints.
///
/// # Errors
///
/// Returns [`Error::Config`](crate::Error::Config) if nothing matches, or
/// [`Error::Store`](crate::Error::Store) if the needle is ambiguous.
pub fn find_quest(engine: &Engine, needle: &str) -> crate::Result<ghostr_core::quest::Quest> {
    engine
        .store()
        .find_quest(engine.dek()?, needle)?
        .ok_or_else(|| crate::Error::Config {
            detail: format!("no quest matching `{needle}`"),
        })
}

/// Records a verdict, and everything that follows from it.
///
/// In order: verify the commitment, write the answer, store the correction as
/// corpus, queue the training delta. The commitment check comes first because a
/// quest that cannot reproduce its own commitment is one whose claim was edited
/// after issue, and answering it would launder a broken guarantee (I6).
///
/// # Errors
///
/// Returns [`Error::Quests`](crate::Error::Quests) if the commitment does not
/// verify, the quest is already answered, or it has expired.
pub fn answer_quest(
    engine: &Engine,
    id: ghostr_core::ids::QuestId,
    verdict: ghostr_core::quest::Verdict,
) -> crate::Result<ghostr_quests::VerdictOutcome> {
    use ghostr_quests::{CorrectionSlot, StandardIntake};

    let dek = engine.dek()?;
    let now = engine.now();
    let quest = get_quest(engine, id)?;

    let mut random = [0u8; 10];
    engine.rng().fill(&mut random);
    let mut salt = [0u8; 32];
    engine.rng().fill(&mut salt);
    let slot = CorrectionSlot {
        source: verdict_source(engine, quest.holdout)?,
        id: MemoryId::new(now.utc_millis().unsigned_abs(), random),
        salt,
    };

    let outcome = StandardIntake.decide(
        &quest,
        &verdict,
        now,
        ghostr_quests::generate::HoldoutPolicy::default().latency_floor_seconds,
        slot,
    )?;

    let elapsed = (now.utc_millis() - quest.issued_at.utc_millis()) as f32 / 1_000.0;
    let mut answered = quest.clone();
    answered.status = ghostr_core::quest::QuestStatus::Answered;
    answered.verdict = Some(verdict);
    engine
        .store()
        .answer_quest(dek, &answered, now, elapsed.max(0.0), engine.nonce())?;

    // Corpus first, then the delta that points at it. The other order would
    // leave a queued delta naming a memory that does not exist if the process
    // died between the two.
    if let Some(memory) = &outcome.memory {
        engine.store().put_memory(dek, memory, engine.nonce())?;
    }
    if let Some(delta) = &outcome.delta {
        engine.store().queue_delta(dek, delta, engine.nonce())?;
    }

    Ok(outcome)
}

/// The fidelity score over a window.
///
/// Held-out, non-decoy, answered quests only — that set is assembled by the
/// store from clear columns, so the scorer is never handed anything else
/// (SPEC I7). Decoys are read separately and feed the integrity signals, which
/// travel beside the number and are never folded into it.
///
/// # Errors
///
/// Returns [`Error::Quests`](crate::Error::Quests) if there are too few scored
/// quests to say anything.
pub fn fidelity(
    engine: &Engine,
    window: ghostr_core::fidelity::ScoreWindow,
) -> crate::Result<ghostr_core::fidelity::FidelityScore> {
    use ghostr_quests::{ScoredQuest, Scorer as _, StandardScorer};

    let dek = engine.dek()?;
    let since = window_start(engine, window);
    let scorer = StandardScorer::default();

    let held_out: Vec<ScoredQuest> = engine
        .store()
        .scoreable_quests(dek, since)?
        .into_iter()
        .map(|(quest, answer_seconds)| ScoredQuest {
            score: scorer.score_quest(&quest),
            quest,
            answer_seconds,
        })
        .collect();

    let decoys: Vec<ScoredQuest> = engine
        .store()
        .decoy_quests(dek, since)?
        .into_iter()
        .map(|(quest, answer_seconds)| ScoredQuest {
            score: scorer.score_quest(&quest),
            quest,
            answer_seconds,
        })
        .collect();

    let mut score = scorer.aggregate(&held_out, window)?;
    score.integrity = scorer.integrity(&held_out, &decoys);
    // Recomputed, because convergence depends on the decoy-confirm rate and the
    // scorer could not see the decoys when it first ran.
    score.converged = scorer.converged(&score);
    score.committed_at_seq = engine.store().tip()?.map_or(0, |tip| tip.seq);
    Ok(score)
}

/// Closes every quest past its expiry.
///
/// # Errors
///
/// Returns [`Error::Store`](crate::Error::Store) if the write fails.
pub fn expire_quests(engine: &Engine) -> crate::Result<u64> {
    Ok(engine.store().expire_quests(engine.now())?)
}

/// The window's start instant.
fn window_start(engine: &Engine, window: ghostr_core::fidelity::ScoreWindow) -> Timestamp {
    use ghostr_core::fidelity::ScoreWindow;

    let days = match window {
        ScoreWindow::Rolling30 => 30,
        ScoreWindow::Rolling90 => 90,
        // Everything. Zero rather than a large negative, because a timestamp
        // before the epoch is a value nothing else in the system produces.
        _ => return Timestamp::new(0, 0),
    };
    let now = engine.now();
    Timestamp::new(
        now.utc_millis().saturating_sub(days * 86_400_000),
        now.offset_seconds(),
    )
}

/// Recent engagement, for the fatigue term and the adaptive daily count.
fn engagement(
    engine: &Engine,
    now: Timestamp,
) -> crate::Result<ghostr_quests::generate::EngagementStats> {
    use ghostr_quests::generate::EngagementStats;

    let since = Timestamp::new(
        now.utc_millis()
            .saturating_sub(QUEST_WINDOW_DAYS * 86_400_000),
        now.offset_seconds(),
    );
    let counts = engine.store().quest_engagement(since)?;

    // A user with no history is treated as fully engaged rather than fully
    // fatigued. The alternative starts everyone at the three-quest floor and
    // gives the loop no way to climb out of it.
    let completion_rate = if counts.issued == 0 {
        1.0
    } else {
        f64::from(counts.answered) as f32 / f64::from(counts.issued) as f32
    };

    let median = if counts.answer_seconds.is_empty() {
        0.0
    } else {
        counts.answer_seconds[counts.answer_seconds.len() / 2]
    };

    Ok(EngagementStats {
        completion_rate,
        median_answer_seconds: median,
        streak_days: streak(&counts.answered_days, now, engine.home_tz()?),
    })
}

/// Consecutive days ending today or yesterday with at least one answer.
///
/// Yesterday counts as still alive: a streak that broke because the user had
/// not yet opened the app today would be a lie told by a clock.
fn streak(days: &[NaiveDate], now: Timestamp, tz: chrono_tz::Tz) -> u32 {
    let today = now.date_in(&tz);
    let Some(&most_recent) = days.first() else {
        return 0;
    };
    if (today - most_recent).num_days() > 1 {
        return 0;
    }

    let mut count = 1;
    let mut cursor = most_recent;
    for &day in days.iter().skip(1) {
        if (cursor - day).num_days() == 1 {
            count += 1;
            cursor = day;
        } else {
            break;
        }
    }
    count
}

/// Exemplar sentences for cloze quests.
///
/// A persona holds exemplar *ids*; the sentences live in the store. A cloze's
/// ground truth has to be something the user really wrote, so a missing or
/// shredded exemplar drops out rather than being replaced.
fn voice_exemplars(
    engine: &Engine,
    persona: &PersonaModel,
) -> crate::Result<Vec<(MemoryId, String)>> {
    let dek = engine.dek()?;
    let mut out = Vec::new();
    for &id in &persona.facets.voice.exemplars {
        match engine.store().get_memory(dek, id) {
            Ok(Some(memory)) => out.push((id, memory.body.text)),
            // A shredded exemplar is gone on purpose (SPEC Q6). Skipping it is
            // the whole point of the shred.
            Ok(None) | Err(ghostr_store::Error::Shredded { .. }) => {}
            Err(e) => return Err(e.into()),
        }
    }
    Ok(out)
}

/// The source verdict-derived memories are filed under, created on first use.
///
/// Two of them, split on holdout. Both are first-party — a held-out correction
/// is no less the user's own words — so the split is by source rather than by
/// trust: softening the trust level to keep it out of distillation would be
/// lying about where the sentence came from.
fn verdict_source(engine: &Engine, holdout: bool) -> crate::Result<SourceId> {
    use ghostr_core::sensitivity::{Sensitivity, TrustLevel};
    use ghostr_store::sqlite::NewSourceRow;

    let mut random = [0u8; 10];
    engine.rng().fill(&mut random);
    Ok(engine.store().upsert_source_with(
        engine.dek()?,
        &NewSourceRow {
            id: SourceId::new(engine.now().utc_millis().unsigned_abs(), random),
            kind_tag: if holdout {
                VERDICT_HOLDOUT_SOURCE_TAG
            } else {
                VERDICT_SOURCE_TAG
            },
            config: "",
            // First-party: these are the user's own words, written deliberately
            // about themselves. They are among the highest-quality signal the
            // corpus receives, and voice profiling should draw on them.
            trust: TrustLevel::FirstParty,
            sensitivity: Sensitivity::Private,
        },
        engine.nonce(),
    )?)
}

#[cfg(test)]
mod commitment_tests {
    use ghostr_core::footage::CommitmentVersion;
    use ghostr_core::hash::{Tag, tagged_hash};
    use ghostr_core::ids::{PersonaVersion, QuestId};
    use ghostr_core::quest::{Facet, Quest, QuestKind, QuestStatus, Verdict};

    use super::*;

    fn quest(n: u8) -> Quest {
        Quest {
            id: QuestId::new(1_700_000_000_000 + u64::from(n), [n; 10]),
            issued_for: NaiveDate::from_ymd_opt(2026, 3, 1).expect("date"),
            issued_at: Timestamp::new(1_700_000_000_000, 0),
            persona_version: PersonaVersion {
                ordinal: 12,
                content: tagged_hash(Tag::Persona, b"v12"),
            },
            kind: QuestKind::FactRecall {
                claim: "you argued with the timezone code again".to_owned(),
                as_of: NaiveDate::from_ymd_opt(2026, 3, 1).expect("date"),
            },
            facet: Facet::Routine,
            difficulty: 0.4,
            evidence: Vec::new(),
            confidence: 0.7,
            answer_commitment: tagged_hash(Tag::QuestAnswer, &[n]),
            nonce: [n; 32],
            holdout: true,
            decoy: false,
            expires_at: Timestamp::new(1_700_000_100_000, 0),
            status: QuestStatus::Open,
            verdict: None,
        }
    }

    fn root_of(
        quests: &QuestActivity<'_>,
        version: CommitmentVersion,
    ) -> ghostr_core::hash::Hash32 {
        build_root(
            &[],
            quests,
            version,
            1,
            NaiveDate::from_ymd_opt(2026, 3, 1).expect("date"),
            &chrono_tz::Tz::UTC,
        )
        .expect("root")
        .0
    }

    /// The property the whole migration rests on. A day with nothing new to
    /// commit to hashes identically under either version — which is why every
    /// chain sealed before quests reached the tree survives this change
    /// untouched, rather than needing a re-seal that immutability forbids.
    #[test]
    fn a_day_with_no_quests_hashes_the_same_under_either_version() {
        let none = QuestActivity {
            issued: &[],
            answered: &[],
        };
        assert_eq!(
            root_of(&none, CommitmentVersion::MemoriesOnly),
            root_of(&none, CommitmentVersion::WithQuests),
        );
    }

    /// And the other half: where there *is* something new, the versions must
    /// disagree. Otherwise the first test passes for the boring reason that the
    /// quests were never being committed at all.
    #[test]
    fn a_day_with_quests_hashes_differently_under_each_version() {
        let issued = [quest(1), quest(2)];
        let activity = QuestActivity {
            issued: &issued,
            answered: &[],
        };
        assert_ne!(
            root_of(&activity, CommitmentVersion::MemoriesOnly),
            root_of(&activity, CommitmentVersion::WithQuests),
        );
    }

    /// A verdict changes the root too, or committing to it bought nothing.
    #[test]
    fn a_verdict_changes_the_root() {
        let issued = [quest(1)];
        let mut answered_quest = quest(2);
        answered_quest.status = QuestStatus::Answered;
        answered_quest.verdict = Some(Verdict::Confirm);
        let answered = [(answered_quest, Timestamp::new(1_700_000_050_000, 0))];

        let without = QuestActivity {
            issued: &issued,
            answered: &[],
        };
        let with = QuestActivity {
            issued: &issued,
            answered: &answered,
        };
        assert_ne!(
            root_of(&without, CommitmentVersion::WithQuests),
            root_of(&with, CommitmentVersion::WithQuests),
        );
    }

    /// The commitment is what a verifier checks, so a quest whose commitment
    /// differs must land on a different leaf even when everything else matches.
    #[test]
    fn the_answer_commitment_is_inside_the_leaf() {
        let mut a = quest(1);
        let mut b = quest(1);
        b.answer_commitment = tagged_hash(Tag::QuestAnswer, b"a different answer");
        assert_ne!(a.answer_commitment, b.answer_commitment);

        // Same nonce, same everything else: only the commitment moves.
        a.status = QuestStatus::Open;
        b.status = QuestStatus::Open;
        let first = [a];
        let second = [b];
        assert_ne!(
            root_of(
                &QuestActivity {
                    issued: &first,
                    answered: &[]
                },
                CommitmentVersion::WithQuests
            ),
            root_of(
                &QuestActivity {
                    issued: &second,
                    answered: &[]
                },
                CommitmentVersion::WithQuests
            ),
        );
    }

    /// I6, structurally. A leaf that carried the claim could not be revealed to
    /// prove inclusion without disclosing what the quest asked — and a quest is
    /// about the user's own life.
    #[test]
    fn a_quest_leaf_preimage_carries_no_claim_text() {
        const CLAIM: &str = "you argued with the timezone code again";
        let payload = quest_payload(&quest(1)).expect("payload");
        let encoded = ghostr_core::canonical::to_canonical_cbor(&payload).expect("cbor");
        assert!(
            !encoded.windows(CLAIM.len()).any(|w| w == CLAIM.as_bytes()),
            "the claim reached the leaf preimage"
        );
    }

    /// A verdict leaf must not carry the user's correction either. The text
    /// became a memory on the same day, so it is already a leaf in this tree.
    #[test]
    fn a_verdict_leaf_preimage_carries_no_correction_text() {
        const WORDS: &str = "I would have said the opposite";
        let verdict = Verdict::Correct {
            correction: WORDS.to_owned(),
            severity: ghostr_core::quest::Severity::Major,
        };
        let encoded = ghostr_core::canonical::to_canonical_cbor(&VerdictLeafPayload {
            quest_id: quest(1).id,
            verdict: verdict_tag(&verdict),
            severity: severity_tag(&verdict),
            answered_at: 1_700_000_050_000,
        })
        .expect("cbor");
        assert!(
            !encoded.windows(WORDS.len()).any(|w| w == WORDS.as_bytes()),
            "a correction reached the leaf preimage"
        );
        assert!(
            encoded.windows(5).any(|w| w == b"major"),
            "severity is kept"
        );
    }

    /// The names in a preimage are frozen. A `Debug` rendering would be a
    /// formatting decision, and one of those changing silently forks every
    /// chain sealed after it.
    #[test]
    fn verdict_names_are_frozen() {
        assert_eq!(verdict_tag(&Verdict::Confirm), "confirm");
        assert_eq!(verdict_tag(&Verdict::Unknown), "unknown");
        assert_eq!(verdict_tag(&Verdict::Reject { note: None }), "reject");
        assert_eq!(
            verdict_tag(&Verdict::Void {
                reason: "broken".to_owned()
            }),
            "void"
        );
        assert_eq!(
            verdict_tag(&Verdict::Correct {
                correction: "no".to_owned(),
                severity: ghostr_core::quest::Severity::Minor,
            }),
            "correct"
        );
    }
}
