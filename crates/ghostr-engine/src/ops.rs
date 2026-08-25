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
use ghostr_core::time::Timestamp;
use ghostr_ingest::markdown;
use ghostr_memoria::compose::{self, NoteExtraction};
use ghostr_memoria::extract;
use ghostr_memoria::pipeline::DraftFootage;
use ghostr_memoria::summarize::{NaiveSummarizer, Summarizer};
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
    let people = compose::people(&notes, &|name| entity_id_for(name));

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
        carried_threads: previous_open.iter().map(|t| t.id).collect(),
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
            },
        ));
    }
    let (root, leaves) = build_root(&memories, seq, date, &tz)?;
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
            leaf_count: u32::try_from(leaves.len() + 1).unwrap_or(u32::MAX),
        },
        sealed_at: engine.now(),
    };

    let nonce = engine.nonce();
    engine.store().seal_footage(dek, &footage, &leaves, nonce)?;
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
fn build_root(
    memories: &[Memory],
    seq: u64,
    date: NaiveDate,
    tz: &chrono_tz::Tz,
) -> crate::Result<(Hash32, Vec<(MemoryId, Hash32)>)> {
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

    Ok((ghostr_anchor::root(digests)?, leaves))
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

/// A deterministic entity id for a name.
///
/// Same name, same id, forever — without an entity table. Real resolution
/// (aliases, merging, pseudonyms) arrives with M1's entity store.
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
