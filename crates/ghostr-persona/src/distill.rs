//! The deterministic distiller.
//!
//! # What is computed, and what needs a model
//!
//! Three of the six facets are measurements and are computed exactly:
//!
//! - **Voice** — arithmetic over the corpus. See [`crate::voice`].
//! - **Relationships** — who appears, how often, and at what cadence. Counting.
//! - **Routines** — which patterns repeat, and how regularly. Counting.
//!
//! Three are not:
//!
//! - **Opinions**, **boundaries**, **lore** — "what does this person think about
//!   X" is not countable. These come from a model, and without one they are
//!   empty rather than guessed.
//!
//! An empty facet is the honest output for a vault with no model. A guessed
//! stance would be a confident claim with no evidence behind it, which is worse
//! than a missing one — and would show up in a quest as the ghost asserting
//! something its owner never said.
//!
//! # Every claim carries evidence
//!
//! This is what makes the symbolic model auditable, and it is enforced rather
//! than intended: [`validate`] rejects a model containing any claim with an
//! empty `evidence` list, and `distill` runs it before returning (SPEC §3.6).

use std::collections::{BTreeMap, BTreeSet};

use ghostr_core::footage::Footage;
use ghostr_core::hash::{Hash32, Tag, tagged_hash};
use ghostr_core::ids::{EntityId, MemoryId, PersonaVersion};
use ghostr_core::memory::Memory;
use ghostr_core::persona::{Facets, PersonaDelta, PersonaModel, Relation, Routine, VoiceProfile};
use ghostr_core::time::Timestamp;

/// How many memories a persona needs before it is worth distilling.
///
/// A ghost built from four notes would be confident and wrong, which is worse
/// than absent. `InsufficientCorpus` is a real state for a new user, not a
/// failure.
pub const MIN_CORPUS: u32 = 20;

/// How many days between a person's appearances before the tie is not a cadence.
const MAX_CADENCE_DAYS: f32 = 90.0;

/// What a distillation reads, as owned data.
///
/// Separate from [`DistillInput`](crate::builder::DistillInput), which borrows:
/// the engine assembles this from the store, and the borrowing form is what the
/// trait takes.
#[derive(Debug, Clone)]
pub struct Corpus<'a> {
    /// Sealed days, oldest first.
    pub footage: &'a [Footage],
    /// The memories eligible to be voice exemplars.
    ///
    /// The caller filters on
    /// [`TrustLevel::may_be_exemplar`](ghostr_core::sensitivity::TrustLevel::may_be_exemplar),
    /// and [`crate::voice::profile`] has no path to anything outside this slice
    /// (THREAT_MODEL §T7).
    pub first_party: &'a [&'a Memory],
    /// The memories a claim may rest on.
    ///
    /// Filtered on
    /// [`TrustLevel::may_source_stance`](ghostr_core::sensitivity::TrustLevel::may_source_stance),
    /// so it also admits `SelfReported` — a people or health log is the user
    /// asserting something about themselves, and excluding it would leave a
    /// habit tracker unable to teach the ghost a habit.
    ///
    /// Relationships and routines are read out of [`Corpus::footage`], which is
    /// compiled from the *whole* day and therefore includes third-party
    /// memories. They take the ids here as the set a claim may rest on. Without
    /// that, a stranger's note could evidence a `Relation` — the second thing
    /// §T7 says an injection is trying to plant, and the one the trust level
    /// alone does not stop.
    pub claimable: &'a [&'a Memory],
}

/// Distils the deterministic facets.
///
/// # Errors
///
/// Returns [`Error::InsufficientCorpus`](crate::Error::InsufficientCorpus) if
/// there is not enough to work from, or
/// [`Error::HoldoutLeak`](crate::Error::HoldoutLeak) if any delta came from a
/// held-out quest.
pub fn distill(
    prior: Option<&PersonaModel>,
    corpus: &Corpus<'_>,
    deltas: &[PersonaDelta],
    now: Timestamp,
    next_ordinal: u32,
) -> crate::Result<PersonaModel> {
    // I7, checked before anything else. A holdout delta reaching here means the
    // fidelity score is being computed on data the model trained on, and every
    // score since is wrong. It fails loudly rather than being filtered out,
    // because a silent filter hides the upstream defect that produced it.
    if deltas.iter().any(|d| d.from_holdout) {
        return Err(crate::Error::HoldoutLeak);
    }

    let corpus_size = u32::try_from(corpus.first_party.len()).unwrap_or(u32::MAX);
    if corpus_size < MIN_CORPUS {
        return Err(crate::Error::InsufficientCorpus {
            have: corpus_size,
            need: MIN_CORPUS,
        });
    }

    // Which memories a claim may rest on. Wider than the voice slice on purpose:
    // narrowing it to first-party would mean a people log could never evidence
    // a relationship, which is the one thing a people log is for.
    let trusted: BTreeSet<MemoryId> = corpus.claimable.iter().map(|m| m.id).collect();

    let mut facets = Facets {
        voice: crate::voice::profile(corpus.first_party),
        // A model's work. Carried forward from the prior version rather than
        // dropped, so a distillation without a model preserves what an earlier
        // one with a model found.
        opinions: prior.map(|p| p.facets.opinions.clone()).unwrap_or_default(),
        relationships: relationships(corpus.footage, &trusted),
        routines: routines(corpus.footage, &trusted),
        boundaries: prior
            .map(|p| p.facets.boundaries.clone())
            .unwrap_or_default(),
        lore: prior.map(|p| p.facets.lore.clone()).unwrap_or_default(),
    };
    apply_deltas(&mut facets, deltas);

    let model = PersonaModel {
        version: PersonaVersion {
            ordinal: next_ordinal,
            content: content_hash(&facets)?,
        },
        parent: prior.map(|p| p.version),
        created_at: now,
        facets,
        // The wider slice, because it is the honest answer to "what fed this":
        // a memory that evidenced a relationship fed the model even though it
        // was never eligible to be a voice exemplar. Recording only the voice
        // slice would leave a claim traceable to a memory the model does not
        // admit reading (THREAT_MODEL §T7's traceability).
        derived_from: corpus.claimable.iter().map(|m| m.id).collect(),
        diff: None,
    };

    validate(&model)?;
    Ok(model)
}

/// Applies queued corrections to the carried-forward facets.
///
/// A correction lowers `strength` and records what contradicted it; it never
/// deletes a claim. One answer is not allowed to overturn a stance backed by
/// fifty memories — the weight has to genuinely shift first, which takes
/// repeated corrections across several distillations (SPEC §4.5).
///
/// Only opinions and lore are touched. Voice, relationships, and routines are
/// re-derived from the corpus on every distillation, so writing a correction
/// into them would be erased by the next run; those facets change when the
/// corpus does — and a correction *is* corpus, because the memory it produced
/// entered it.
fn apply_deltas(facets: &mut Facets, deltas: &[PersonaDelta]) {
    use ghostr_core::quest::Facet;

    for delta in deltas {
        match delta.facet {
            Facet::Opinion => {
                for stance in facets
                    .opinions
                    .iter_mut()
                    .filter(|s| s.evidence.contains(&delta.memory_id))
                {
                    stance.strength = (stance.strength - delta.weight).clamp(0.0, 1.0);
                    // Held explicitly rather than resolved away: a stance that
                    // has been argued with is a different thing from one that
                    // has merely faded, and the diff should say which.
                    if let Some(correction) = delta.correction_id
                        && !stance.contradicted_by.contains(&correction)
                    {
                        stance.contradicted_by.push(correction);
                    }
                }
            }
            Facet::Lore => {
                for fact in facets
                    .lore
                    .iter_mut()
                    .filter(|l| l.evidence.contains(&delta.memory_id))
                {
                    fact.confidence = (fact.confidence - delta.weight).clamp(0.0, 1.0);
                }
            }
            _ => {}
        }
    }
}

/// Rejects a model carrying any claim without evidence.
///
/// The audit trail is the reason the model is symbolic at all, so an
/// unsupported claim is not a quality problem — it is the property being
/// broken. Runs on every distillation, including a model-produced one, because
/// a hallucinated stance is exactly what this catches (SPEC §3.6).
///
/// # Errors
///
/// Returns [`Error::UnsupportedClaim`](crate::Error::UnsupportedClaim).
pub fn validate(model: &PersonaModel) -> crate::Result<()> {
    let unsupported = model.facets.opinions.iter().any(|s| s.evidence.is_empty())
        || model
            .facets
            .relationships
            .iter()
            .any(|r| r.evidence.is_empty())
        || model.facets.routines.iter().any(|r| r.evidence.is_empty())
        || model
            .facets
            .boundaries
            .iter()
            .any(|b| b.evidence.is_empty())
        || model.facets.lore.iter().any(|l| l.evidence.is_empty());

    if unsupported {
        return Err(crate::Error::UnsupportedClaim);
    }
    Ok(())
}

/// The content hash that identifies a version.
///
/// Over canonical CBOR, so one set of facets has exactly one version identity —
/// two distillations that found the same thing are the same version, and a
/// version identifier can be compared without comparing the model.
///
/// # Errors
///
/// Returns [`Error::UnsupportedClaim`](crate::Error::UnsupportedClaim) if the
/// facets cannot be canonically encoded, which for a persona means a float
/// outside the fixed-point conversion — a bug, not a user state.
pub fn content_hash(facets: &Facets) -> crate::Result<Hash32> {
    let bytes = canonical_facets(facets)?;
    Ok(tagged_hash(Tag::Persona, &bytes))
}

/// Encodes facets for hashing.
///
/// Canonical CBOR rejects floats, and a persona is full of them, so every ratio
/// is converted to fixed point first. That conversion is the *definition* of the
/// version identity: two personas whose strengths differ below the fixed-point
/// resolution are the same version, deliberately, because a version bump on
/// noise is a version bump nobody can review.
fn canonical_facets(facets: &Facets) -> crate::Result<Vec<u8>> {
    use ghostr_core::canonical::{ratio_to_fixed, signed_ratio_to_fixed, to_canonical_cbor};

    #[derive(serde::Serialize)]
    struct Hashable {
        register: [u32; 4],
        lexicon: Vec<(String, u32)>,
        syntax: [u32; 4],
        punctuation: [u32; 5],
        exemplars: Vec<String>,
        opinions: Vec<(String, String, u32)>,
        relationships: Vec<(String, u32)>,
        routines: Vec<(String, String, u32)>,
        boundaries: Vec<(String, u32)>,
        lore: Vec<(String, u32)>,
    }

    let v = &facets.voice;
    let hashable = Hashable {
        register: [
            ratio_to_fixed(v.register.formality, "formality")?,
            ratio_to_fixed(v.register.warmth, "warmth")?,
            ratio_to_fixed(v.register.hedging, "hedging")?,
            ratio_to_fixed(v.register.profanity, "profanity")?,
        ],
        lexicon: v
            .lexicon
            .iter()
            .map(|t| {
                Ok((
                    t.phrase.clone(),
                    ratio_to_fixed(t.distinctiveness, "distinctiveness")?,
                ))
            })
            .collect::<crate::Result<Vec<_>>>()?,
        syntax: [
            // Sentence lengths are not ratios, so they are scaled and rounded
            // rather than converted: a mean of 14.3 words is 143 here.
            (v.syntax.mean_sentence_words * 10.0).round().max(0.0) as u32,
            (v.syntax.sentence_words_stddev * 10.0).round().max(0.0) as u32,
            (v.syntax.mean_clause_depth * 10.0).round().max(0.0) as u32,
            ratio_to_fixed(v.syntax.fragment_rate, "fragment_rate")?,
        ],
        punctuation: [
            (v.punctuation.em_dash_rate * 10.0).round().max(0.0) as u32,
            ratio_to_fixed(v.punctuation.lowercase_start_rate, "lowercase_start_rate")?,
            (v.punctuation.emoji_rate * 10.0).round().max(0.0) as u32,
            (v.punctuation.ellipsis_rate * 10.0).round().max(0.0) as u32,
            ratio_to_fixed(v.punctuation.unterminated_rate, "unterminated_rate")?,
        ],
        exemplars: v.exemplars.iter().map(ToString::to_string).collect(),
        opinions: facets
            .opinions
            .iter()
            .map(|s| {
                Ok((
                    s.topic.clone(),
                    s.position.clone(),
                    ratio_to_fixed(s.strength, "strength")?,
                ))
            })
            .collect::<crate::Result<Vec<_>>>()?,
        relationships: facets
            .relationships
            .iter()
            .map(|r| {
                Ok((
                    r.entity.to_string(),
                    ratio_to_fixed(r.closeness, "closeness")?,
                ))
            })
            .collect::<crate::Result<Vec<_>>>()?,
        routines: facets
            .routines
            .iter()
            .map(|r| {
                Ok((
                    r.pattern.clone(),
                    r.schedule.clone(),
                    ratio_to_fixed(r.confidence, "confidence")?,
                ))
            })
            .collect::<crate::Result<Vec<_>>>()?,
        boundaries: facets
            .boundaries
            .iter()
            .map(|b| {
                Ok((
                    b.description.clone(),
                    ratio_to_fixed(b.firmness, "firmness")?,
                ))
            })
            .collect::<crate::Result<Vec<_>>>()?,
        lore: facets
            .lore
            .iter()
            .map(|l| {
                Ok((
                    l.statement.clone(),
                    ratio_to_fixed(l.confidence, "confidence")?,
                ))
            })
            .collect::<crate::Result<Vec<_>>>()?,
    };
    // `signed_ratio_to_fixed` is unused here only because no facet field is
    // signed yet; naming it keeps the import honest if one is added.
    let _ = signed_ratio_to_fixed;

    to_canonical_cbor(&hashable).map_err(|_| crate::Error::UnsupportedClaim)
}

/// Who the user knows, from person beats across the run.
///
/// `trusted` is the set of memory ids a claim may rest on. A beat evidenced
/// only by third-party memories is not an appearance: a stranger mentioning
/// somebody in a feed note is not the user seeing them (THREAT_MODEL §T7).
fn relationships(footage: &[Footage], trusted: &BTreeSet<MemoryId>) -> Vec<Relation> {
    struct Seen {
        appearances: u32,
        evidence: Vec<MemoryId>,
        first_day: i64,
        last_day: i64,
        valence_sum: f32,
        valence_count: u32,
    }

    let mut by_entity: BTreeMap<EntityId, Seen> = BTreeMap::new();
    let mut days = 0i64;

    for (index, day) in footage.iter().enumerate() {
        days = i64::try_from(index).unwrap_or(0);
        for beat in &day.people {
            // Filtered before anything is counted, not after. Counting the
            // appearance and then dropping its evidence would leave `closeness`
            // inflated by sightings the user never had.
            let evidence: Vec<MemoryId> = beat
                .memory_ids
                .iter()
                .copied()
                .filter(|id| trusted.contains(id))
                .collect();
            if evidence.is_empty() {
                continue;
            }
            let entry = by_entity.entry(beat.entity).or_insert_with(|| Seen {
                appearances: 0,
                evidence: Vec::new(),
                first_day: days,
                last_day: days,
                valence_sum: 0.0,
                valence_count: 0,
            });
            entry.appearances += 1;
            entry.last_day = days;
            entry.evidence.extend(evidence);
            if let Some(v) = beat.valence {
                entry.valence_sum += v;
                entry.valence_count += 1;
            }
        }
    }

    let total_days = (days + 1).max(1) as f32;
    let mut out: Vec<Relation> = by_entity
        .into_iter()
        .filter(|(_, seen)| !seen.evidence.is_empty())
        .map(|(entity, seen)| {
            let span = (seen.last_day - seen.first_day).max(0) as f32;
            // Cadence needs at least two appearances to be a gap rather than a
            // single point. One sighting is not a rhythm.
            let cadence_days = if seen.appearances > 1 && span > 0.0 {
                let gap = span / (seen.appearances - 1) as f32;
                (gap <= MAX_CADENCE_DAYS).then_some(gap)
            } else {
                None
            };
            Relation {
                entity,
                // The role needs a model. An empty string is the honest
                // placeholder; guessing "colleague" from a frequency would be
                // a claim the evidence does not support.
                role: String::new(),
                closeness: (seen.appearances as f32 / total_days).clamp(0.0, 1.0),
                cadence_days,
                topics: Vec::new(),
                evidence: dedup(seen.evidence),
            }
        })
        .collect();

    out.sort_by(|a, b| {
        b.closeness
            .partial_cmp(&a.closeness)
            .unwrap_or(core::cmp::Ordering::Equal)
            .then_with(|| a.entity.cmp(&b.entity))
    });
    out
}

/// What recurs.
///
/// A routine is a thread title that has been *opened more than once* — the
/// groceries, the weekly review, the thing that keeps coming back. Counting how
/// many days a thread appears in `open_threads` would instead measure how long a
/// single to-do stayed open, which is the opposite fact: one lease renewal
/// carried forward for a month would read as the strongest routine in the
/// corpus, and a genuine weekly habit would read as weaker.
///
/// Distinct thread ids under one title is the signal, because `compose::threads`
/// allocates a new id when a closed title reopens.
///
/// `trusted` is the set of memory ids a claim may rest on, for the same reason
/// it applies to relationships: a thread the user never wrote in is not their
/// routine, however often a feed brings it back up (THREAT_MODEL §T7).
fn routines(footage: &[Footage], trusted: &BTreeSet<MemoryId>) -> Vec<Routine> {
    use ghostr_core::ids::ThreadId;

    let mut by_title: BTreeMap<String, (BTreeSet<ThreadId>, Vec<MemoryId>)> = BTreeMap::new();

    for day in footage {
        for thread in &day.open_threads {
            let evidence: Vec<MemoryId> = thread
                .memory_ids
                .iter()
                .copied()
                .filter(|id| trusted.contains(id))
                .collect();
            if evidence.is_empty() {
                continue;
            }
            let entry = by_title.entry(thread.title.clone()).or_default();
            entry.0.insert(thread.id);
            entry.1.extend(evidence);
        }
    }

    let total_days = footage.len().max(1) as f32;
    let mut out: Vec<Routine> = by_title
        .into_iter()
        // Opened once is an event, not a routine. Three is the point at which
        // "this keeps happening" is supportable from the evidence.
        .filter(|(_, (ids, evidence))| ids.len() >= 3 && !evidence.is_empty())
        .map(|(pattern, (ids, evidence))| {
            let occurrences = ids.len();
            Routine {
                pattern,
                // A human-readable schedule needs a model. How often it came
                // back is what the corpus actually supports.
                schedule: format!("came back {occurrences} times in {} day(s)", footage.len()),
                confidence: (occurrences as f32 / total_days).clamp(0.0, 1.0),
                evidence: dedup(evidence),
            }
        })
        .collect();

    out.sort_by(|a, b| {
        b.confidence
            .partial_cmp(&a.confidence)
            .unwrap_or(core::cmp::Ordering::Equal)
            .then_with(|| a.pattern.cmp(&b.pattern))
    });
    out
}

/// Deduplicates while keeping a stable order.
fn dedup(mut ids: Vec<MemoryId>) -> Vec<MemoryId> {
    ids.sort_unstable();
    ids.dedup();
    ids
}

/// Whether a distillation is worth running.
///
/// Expensive on a local model, and a version bump adds noise without adding
/// information, so the cadence is weekly or on a delta threshold rather than
/// continuous (SPEC §6.4).
#[must_use]
pub fn should_distill(
    since: Timestamp,
    now: Timestamp,
    pending: &[PersonaDelta],
    weekly: bool,
) -> bool {
    /// Corrections that justify a distillation on their own.
    const DELTA_THRESHOLD: usize = 10;
    /// A week, in milliseconds.
    const WEEK_MS: i64 = 7 * 24 * 60 * 60 * 1_000;

    if pending.len() >= DELTA_THRESHOLD {
        return true;
    }
    weekly && now.utc_millis().saturating_sub(since.utc_millis()) >= WEEK_MS
}

/// The voice profile of an empty corpus.
///
/// Exposed so a caller can build a placeholder model without reaching into
/// `voice` for the empty case.
#[must_use]
pub fn empty_voice() -> VoiceProfile {
    crate::voice::profile(&[])
}

#[cfg(test)]
pub(crate) mod fixtures {
    use ghostr_core::footage::{
        Commitment, Footage, InteractionKind, MoodBasis, MoodReading, PersonBeat, Thread,
        ThreadState,
    };
    use ghostr_core::hash::{Hash32, Tag, tagged_hash};
    use ghostr_core::ids::{SourceId, ThreadId};
    use ghostr_core::memory::{MemoryBody, MemoryKind, Provenance};
    use ghostr_core::sensitivity::Sensitivity;

    use super::*;

    pub(crate) fn memory(n: u16, text: &str) -> Memory {
        let source = SourceId::new(1, [0u8; 10]);
        let byte = u8::try_from(n % 251).unwrap_or(0);
        Memory {
            id: MemoryId::new(u64::from(n) + 1, [byte; 10]),
            source_id: source,
            occurred_at: Some(Timestamp::new(i64::from(n) * 86_400_000, 0)),
            ingested_at: Timestamp::new(0, 0),
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
                source_id: source,
                external_id: None,
                url: None,
                raw_hash: tagged_hash(Tag::MemoryLeaf, &n.to_le_bytes()),
            },
            salt: [byte; 32],
            supersedes: None,
            embedding: None,
        }
    }

    /// A corpus large enough to distil.
    pub(crate) fn corpus_memories(count: u16) -> Vec<Memory> {
        (0..count)
            .map(|n| {
                memory(
                    n,
                    &format!("Day {n}: worked on the parser and it behaved itself today."),
                )
            })
            .collect()
    }

    pub(crate) fn day(seq: u64, people: Vec<PersonBeat>, threads: Vec<Thread>) -> Footage {
        Footage {
            seq,
            date: chrono::NaiveDate::from_ymd_opt(2026, 1, 5)
                .unwrap_or_default()
                .checked_add_days(chrono::Days::new(seq))
                .unwrap_or_default(),
            tz: chrono_tz::UTC,
            window: (Timestamp::new(0, 0), Timestamp::new(86_400_000, 0)),
            empty: false,
            highlights: Vec::new(),
            people,
            mood: MoodReading {
                valence: 0.0,
                arousal: 0.0,
                labels: Vec::new(),
                confidence: 0.0,
                basis: MoodBasis::Inferred,
            },
            open_threads: threads,
            closed_loops: Vec::new(),
            unresolved: Vec::new(),
            memory_ids: Vec::new(),
            amendments: Vec::new(),
            persona_version: PersonaVersion::genesis(),
            commitment: Commitment {
                merkle_root: Hash32::zero(),
                prev_link: Hash32::zero(),
                link: Hash32::zero(),
                leaf_count: 1,
            },
            sealed_at: Timestamp::new(0, 0),
        }
    }

    pub(crate) fn beat(entity: EntityId, memory: MemoryId) -> PersonBeat {
        PersonBeat {
            entity,
            interaction: InteractionKind::Mentioned,
            valence: None,
            memory_ids: vec![memory],
        }
    }

    pub(crate) fn thread(id: ThreadId, title: &str, memory: MemoryId) -> Thread {
        Thread {
            id,
            title: title.to_owned(),
            opened_seq: 1,
            last_touched_seq: 1,
            state: ThreadState::Open,
            memory_ids: vec![memory],
        }
    }

    pub(crate) fn entity(n: u8) -> EntityId {
        EntityId::new(u64::from(n) + 1, [n; 10])
    }
}

#[cfg(test)]
mod tests {
    use ghostr_core::quest::Facet;

    use super::fixtures::*;
    use super::*;

    fn distil(footage: &[Footage], memories: &[Memory]) -> crate::Result<PersonaModel> {
        distil_with(footage, memories, memories)
    }

    /// Distils with the two slices apart: `voice` may be an exemplar, `claims`
    /// may evidence a claim. Every real vault has `voice` as a subset of
    /// `claims`, and the tests that care about the difference say so here.
    fn distil_with(
        footage: &[Footage],
        voice: &[Memory],
        claims: &[Memory],
    ) -> crate::Result<PersonaModel> {
        let voice_refs: Vec<&Memory> = voice.iter().collect();
        let claim_refs: Vec<&Memory> = claims.iter().collect();
        let corpus = Corpus {
            footage,
            first_party: &voice_refs,
            claimable: &claim_refs,
        };
        distill(None, &corpus, &[], Timestamp::new(1_000, 0), 1)
    }

    /// SPEC I7, and the reason this is checked before anything else: a holdout
    /// delta reaching distillation means the fidelity score is computed on data
    /// the model trained on, and every score since is wrong.
    #[test]
    fn a_holdout_delta_is_refused_rather_than_filtered() {
        let memories = corpus_memories(30);
        let refs: Vec<&Memory> = memories.iter().collect();
        let corpus = Corpus {
            footage: &[],
            first_party: &refs,
            claimable: &refs,
        };
        let leaked = PersonaDelta {
            facet: Facet::Opinion,
            memory_id: memories[0].id,
            correction_id: None,
            weight: 1.0,
            queued_at: Timestamp::new(0, 0),
            from_holdout: true,
        };
        let err =
            distill(None, &corpus, &[leaked], Timestamp::new(0, 0), 1).expect_err("must refuse");
        assert!(matches!(err, crate::Error::HoldoutLeak));
    }

    /// It is checked *first*, so a leak is reported even when the corpus is
    /// also too small — the more serious problem is the one that surfaces.
    #[test]
    fn a_holdout_leak_outranks_an_insufficient_corpus() {
        let memories = corpus_memories(2);
        let refs: Vec<&Memory> = memories.iter().collect();
        let corpus = Corpus {
            footage: &[],
            first_party: &refs,
            claimable: &refs,
        };
        let leaked = PersonaDelta {
            facet: Facet::Opinion,
            memory_id: memories[0].id,
            correction_id: None,
            weight: 1.0,
            queued_at: Timestamp::new(0, 0),
            from_holdout: false,
        };
        let mut leaked = leaked;
        leaked.from_holdout = true;
        assert!(matches!(
            distill(None, &corpus, &[leaked], Timestamp::new(0, 0), 1),
            Err(crate::Error::HoldoutLeak)
        ));
    }

    /// A ghost built from four notes would be confident and wrong, which is
    /// worse than absent. This is a real state for a new user, not a failure.
    #[test]
    fn too_small_a_corpus_refuses_to_distil() {
        let memories = corpus_memories(5);
        let err = distil(&[], &memories).expect_err("must refuse");
        assert!(matches!(
            err,
            crate::Error::InsufficientCorpus { have: 5, need: 20 }
        ));
    }

    #[test]
    fn a_sufficient_corpus_distils() {
        let memories = corpus_memories(30);
        let model = distil(&[], &memories).expect("distil");
        assert_eq!(model.version.ordinal, 1);
        assert_eq!(model.derived_from.len(), 30);
        assert!(model.parent.is_none());
        assert!(!model.facets.voice.lexicon.is_empty());
    }

    /// Two distillations that found the same thing are the same version. A
    /// version identity that changed on re-running would make "which model
    /// answered this quest" unanswerable.
    #[test]
    fn the_same_facets_hash_to_the_same_version() {
        let memories = corpus_memories(30);
        let a = distil(&[], &memories).expect("a");
        let b = distil(&[], &memories).expect("b");
        assert_eq!(a.version.content, b.version.content);
    }

    #[test]
    fn different_facets_hash_differently() {
        let a = distil(&[], &corpus_memories(30)).expect("a");
        let mut different = corpus_memories(30);
        different.push(memory(
            99,
            "Something else entirely, at some length, about other things.",
        ));
        let b = distil(&[], &different).expect("b");
        assert_ne!(a.version.content, b.version.content);
    }

    /// Counting, not guessing: who appears and how often.
    #[test]
    fn relationships_come_from_person_beats() {
        let memories = corpus_memories(30);
        let alice = entity(1);
        let bob = entity(2);
        let footage: Vec<Footage> = (0..10)
            .map(|seq| {
                let mut people = vec![beat(alice, memories[seq as usize].id)];
                // Bob appears a third as often.
                if seq % 3 == 0 {
                    people.push(beat(bob, memories[seq as usize].id));
                }
                day(seq + 1, people, Vec::new())
            })
            .collect();

        let model = distil(&footage, &memories).expect("distil");
        assert_eq!(model.facets.relationships.len(), 2);
        // Ordered by closeness, so the person who appears most comes first.
        assert_eq!(model.facets.relationships[0].entity, alice);
        assert!(model.facets.relationships[0].closeness > model.facets.relationships[1].closeness);
    }

    /// THREAT_MODEL §T7. Footage covers the whole day, third-party memories
    /// included, so a beat can rest on a note the user never wrote. Neither the
    /// claim nor the closeness it carries may come from one.
    ///
    /// The attack this stops: a feed note naming `@attacker` produces a person
    /// beat, and without this filter the ghost acquires a relationship with
    /// somebody it has never heard the user mention.
    #[test]
    fn a_beat_evidenced_only_by_third_party_memories_makes_no_relationship() {
        let memories = corpus_memories(30);
        // Not in `first_party`, which is what makes it third-party here: the
        // caller filters, and this slice is the whole trust boundary.
        let stranger = memory(200, "a note the user never wrote");

        let footage: Vec<Footage> = (0..6)
            .map(|seq| {
                day(
                    seq + 1,
                    vec![
                        beat(entity(1), memories[seq as usize].id),
                        beat(entity(9), stranger.id),
                    ],
                    Vec::new(),
                )
            })
            .collect();

        let model = distil(&footage, &memories).expect("distil");
        let entities: Vec<_> = model
            .facets
            .relationships
            .iter()
            .map(|r| r.entity)
            .collect();
        assert!(entities.contains(&entity(1)));
        assert!(
            !entities.contains(&entity(9)),
            "a feed note produced a relationship"
        );
        for relation in &model.facets.relationships {
            assert!(!relation.evidence.contains(&stranger.id));
        }
    }

    /// A self-reported source may evidence a relationship, and may never be a
    /// voice exemplar.
    ///
    /// `TrustLevel` draws that line itself — `may_source_stance` admits
    /// `SelfReported`, `may_be_exemplar` does not — and this is the test that
    /// makes the two predicates mean something rather than being documentation.
    ///
    /// The failure it guards: a people log records "saw Nan" every week, and a
    /// ghost that filtered claims down to prose would never learn the one fact
    /// that log exists to record.
    #[test]
    fn a_self_reported_memory_may_evidence_a_claim_but_not_the_voice() {
        use ghostr_core::sensitivity::TrustLevel;

        // The rule, as the type states it.
        assert!(TrustLevel::SelfReported.may_source_stance());
        assert!(!TrustLevel::SelfReported.may_be_exemplar());

        let prose = corpus_memories(30);
        // Longer than every prose memory in the corpus, so it sorts *first*
        // among exemplar candidates. A short row would be filtered out by
        // `MIN_EXEMPLAR_WORDS` and the assertion below would pass whatever the
        // code did — which is exactly how the first draft of this test passed.
        let logged = memory(
            210,
            "Saw Nan at the clinic on Tuesday morning again, third week running now",
        );
        let mut claims = prose.clone();
        claims.push(logged.clone());

        let footage: Vec<Footage> = (0..6)
            .map(|seq| day(seq + 1, vec![beat(entity(4), logged.id)], Vec::new()))
            .collect();

        let model = distil_with(&footage, &prose, &claims).expect("distil");

        // The claim is made, and rests on the logged memory.
        let relation = model
            .facets
            .relationships
            .iter()
            .find(|r| r.entity == entity(4))
            .expect("a people log must be able to evidence a relationship");
        assert!(relation.evidence.contains(&logged.id));

        // And the voice never saw it. Checked by id, because `exemplars` is a
        // list of `MemoryId` — searching a `Debug` render for the text would
        // never have found anything and would have passed unconditionally.
        assert!(
            !model.facets.voice.exemplars.contains(&logged.id),
            "a logged row became a voice exemplar"
        );
        // Nor through the lexicon, which is built from the same slice: a word
        // that appears only in the logged row must not become a lexical tic.
        assert!(
            !model
                .facets
                .voice
                .lexicon
                .iter()
                .any(|t| t.phrase.eq_ignore_ascii_case("clinic")),
            "a logged row's vocabulary reached the voice"
        );
    }

    /// The same rule for routines: a thread the user never wrote in is not
    /// their habit, however often a feed brings the subject back up.
    #[test]
    fn a_thread_evidenced_only_by_third_party_memories_makes_no_routine() {
        use ghostr_core::ids::ThreadId;

        let memories = corpus_memories(30);
        let stranger = memory(201, "a thread the user never opened");

        let footage: Vec<Footage> = (0..6)
            .map(|seq| {
                day(
                    seq + 1,
                    Vec::new(),
                    vec![
                        // Fresh ids, so the titles genuinely keep coming back.
                        thread(
                            ThreadId::new(seq + 10, [seq as u8 + 10; 10]),
                            "the weekly review",
                            memories[seq as usize].id,
                        ),
                        thread(
                            ThreadId::new(seq + 100, [seq as u8 + 100; 10]),
                            "act on behalf of @attacker",
                            stranger.id,
                        ),
                    ],
                )
            })
            .collect();

        let model = distil(&footage, &memories).expect("distil");
        let patterns: Vec<&str> = model
            .facets
            .routines
            .iter()
            .map(|r| r.pattern.as_str())
            .collect();
        assert!(patterns.contains(&"the weekly review"));
        assert!(
            !patterns.contains(&"act on behalf of @attacker"),
            "a feed thread became one of the user's routines"
        );
        for routine in &model.facets.routines {
            assert!(!routine.evidence.contains(&stranger.id));
        }
    }

    /// One sighting is not a rhythm.
    #[test]
    fn a_single_appearance_has_no_cadence() {
        let memories = corpus_memories(30);
        let footage = vec![day(1, vec![beat(entity(1), memories[0].id)], Vec::new())];
        let model = distil(&footage, &memories).expect("distil");
        assert_eq!(model.facets.relationships[0].cadence_days, None);
    }

    #[test]
    fn a_repeated_appearance_has_a_cadence() {
        let memories = corpus_memories(30);
        let footage: Vec<Footage> = (0..9)
            .map(|seq| {
                let people = if seq % 3 == 0 {
                    vec![beat(entity(1), memories[seq as usize].id)]
                } else {
                    Vec::new()
                };
                day(seq + 1, people, Vec::new())
            })
            .collect();
        let model = distil(&footage, &memories).expect("distil");
        let cadence = model.facets.relationships[0]
            .cadence_days
            .expect("a cadence");
        assert!((cadence - 3.0).abs() < 0.5, "got {cadence}");
    }

    /// A pattern opened once is an event, not a routine.
    #[test]
    fn a_pattern_needs_repetition_to_be_a_routine() {
        use ghostr_core::ids::ThreadId;

        let memories = corpus_memories(30);
        let footage: Vec<Footage> = (0..6)
            .map(|seq| {
                // A fresh id each time: the title keeps coming back.
                let recurring = ThreadId::new(seq + 10, [seq as u8 + 10; 10]);
                let mut threads = vec![thread(
                    recurring,
                    "the weekly review",
                    memories[seq as usize].id,
                )];
                if seq == 0 {
                    threads.push(thread(
                        ThreadId::new(1, [1u8; 10]),
                        "a one-off errand",
                        memories[1].id,
                    ));
                }
                day(seq + 1, Vec::new(), threads)
            })
            .collect();

        let model = distil(&footage, &memories).expect("distil");
        let patterns: Vec<&str> = model
            .facets
            .routines
            .iter()
            .map(|r| r.pattern.as_str())
            .collect();
        assert!(patterns.contains(&"the weekly review"));
        assert!(!patterns.contains(&"a one-off errand"));
    }

    /// The bug this signal replaced. A single to-do carried forward for a month
    /// is one open item, not the strongest routine in the corpus — counting
    /// day-appearances measured how long something stayed open, which is the
    /// opposite fact.
    #[test]
    fn a_single_thread_carried_forward_is_not_a_routine() {
        use ghostr_core::ids::ThreadId;

        let memories = corpus_memories(30);
        let lease = ThreadId::new(1, [1u8; 10]);
        let footage: Vec<Footage> = (0..29)
            .map(|seq| {
                day(
                    seq + 1,
                    Vec::new(),
                    vec![thread(lease, "renew the lease", memories[0].id)],
                )
            })
            .collect();

        let model = distil(&footage, &memories).expect("distil");
        assert!(
            model.facets.routines.is_empty(),
            "one carried-forward to-do became {:?}",
            model.facets.routines
        );
    }

    /// SPEC §3.6. Every claim traces to a memory; one that does not is a
    /// hallucination, and admitting it breaks the audit trail the symbolic
    /// model exists to provide.
    #[test]
    fn every_claim_in_a_distilled_model_carries_evidence() {
        let memories = corpus_memories(30);
        let footage: Vec<Footage> = (0..6)
            .map(|seq| {
                day(
                    seq + 1,
                    vec![beat(entity(1), memories[seq as usize].id)],
                    vec![thread(
                        // A new id each day: the title recurs, which is what
                        // makes it a routine rather than one open item.
                        ghostr_core::ids::ThreadId::new(seq + 1, [seq as u8 + 1; 10]),
                        "a repeating thing",
                        memories[seq as usize].id,
                    )],
                )
            })
            .collect();
        let model = distil(&footage, &memories).expect("distil");
        validate(&model).expect("every claim is supported");
        assert!(!model.facets.relationships.is_empty());
        assert!(!model.facets.routines.is_empty());
    }

    #[test]
    fn validation_rejects_a_claim_with_no_evidence() {
        use ghostr_core::persona::LoreFact;

        let memories = corpus_memories(30);
        let mut model = distil(&[], &memories).expect("distil");
        model.facets.lore.push(LoreFact {
            statement: "the user lives in a lighthouse".to_owned(),
            confidence: 0.9,
            evidence: Vec::new(),
        });
        assert!(matches!(
            validate(&model),
            Err(crate::Error::UnsupportedClaim)
        ));
    }

    /// A distillation without a model must not erase what a distillation with
    /// one found.
    #[test]
    fn model_derived_facets_are_carried_forward() {
        use ghostr_core::persona::Stance;

        let memories = corpus_memories(30);
        let mut prior = distil(&[], &memories).expect("prior");
        prior.facets.opinions.push(Stance {
            topic: "remote work".to_owned(),
            position: "prefers it".to_owned(),
            strength: 0.8,
            stability: 0.7,
            evidence: vec![memories[0].id],
            last_seen: Timestamp::new(0, 0),
            contradicted_by: Vec::new(),
        });

        let refs: Vec<&Memory> = memories.iter().collect();
        let corpus = Corpus {
            footage: &[],
            first_party: &refs,
            claimable: &refs,
        };
        let next =
            distill(Some(&prior), &corpus, &[], Timestamp::new(2_000, 0), 2).expect("distil");

        assert_eq!(next.facets.opinions.len(), 1);
        assert_eq!(next.parent, Some(prior.version));
        assert_eq!(next.version.ordinal, 2);
    }

    /// SPEC §4.5. A correction lowers a stance and records what argued with it.
    /// It never deletes the stance: people are inconsistent, and a model that
    /// resolves that away is modelling a simpler person than the one it clones.
    #[test]
    fn a_correction_weakens_a_stance_without_erasing_it() {
        use ghostr_core::persona::Stance;

        let memories = corpus_memories(30);
        let mut prior = distil(&[], &memories).expect("prior");
        prior.facets.opinions.push(Stance {
            topic: "remote work".to_owned(),
            position: "prefers it".to_owned(),
            strength: 0.8,
            stability: 0.7,
            evidence: vec![memories[0].id],
            last_seen: Timestamp::new(0, 0),
            contradicted_by: Vec::new(),
        });

        let refs: Vec<&Memory> = memories.iter().collect();
        let corpus = Corpus {
            footage: &[],
            first_party: &refs,
            claimable: &refs,
        };
        let correction = MemoryId::new(999, [9u8; 10]);
        let delta = PersonaDelta {
            facet: Facet::Opinion,
            memory_id: memories[0].id,
            correction_id: Some(correction),
            weight: 0.3,
            queued_at: Timestamp::new(0, 0),
            from_holdout: false,
        };

        let next =
            distill(Some(&prior), &corpus, &[delta], Timestamp::new(2_000, 0), 2).expect("distil");

        let stance = &next.facets.opinions[0];
        assert!((stance.strength - 0.5).abs() < 1e-6, "0.8 - 0.3");
        assert_eq!(stance.contradicted_by, vec![correction]);
        assert_eq!(stance.position, "prefers it", "the stance survives");
    }

    /// One answer must not overturn a stance backed by fifty memories, so a
    /// delta against evidence the stance does not rest on changes nothing.
    #[test]
    fn a_delta_against_unrelated_evidence_leaves_a_stance_alone() {
        use ghostr_core::persona::Stance;

        let memories = corpus_memories(30);
        let mut prior = distil(&[], &memories).expect("prior");
        prior.facets.opinions.push(Stance {
            topic: "remote work".to_owned(),
            position: "prefers it".to_owned(),
            strength: 0.8,
            stability: 0.7,
            evidence: vec![memories[0].id],
            last_seen: Timestamp::new(0, 0),
            contradicted_by: Vec::new(),
        });

        let refs: Vec<&Memory> = memories.iter().collect();
        let corpus = Corpus {
            footage: &[],
            first_party: &refs,
            claimable: &refs,
        };
        let delta = PersonaDelta {
            facet: Facet::Opinion,
            memory_id: memories[7].id,
            correction_id: None,
            weight: 0.5,
            queued_at: Timestamp::new(0, 0),
            from_holdout: false,
        };

        let next =
            distill(Some(&prior), &corpus, &[delta], Timestamp::new(2_000, 0), 2).expect("distil");
        assert!((next.facets.opinions[0].strength - 0.8).abs() < 1e-6);
    }

    /// Repeated corrections do accumulate — that is how the weight genuinely
    /// shifts — but strength floors at zero rather than going negative.
    #[test]
    fn corrections_accumulate_and_floor_at_zero() {
        use ghostr_core::persona::Stance;

        let memories = corpus_memories(30);
        let mut prior = distil(&[], &memories).expect("prior");
        prior.facets.opinions.push(Stance {
            topic: "remote work".to_owned(),
            position: "prefers it".to_owned(),
            strength: 0.5,
            stability: 0.7,
            evidence: vec![memories[0].id],
            last_seen: Timestamp::new(0, 0),
            contradicted_by: Vec::new(),
        });

        let refs: Vec<&Memory> = memories.iter().collect();
        let corpus = Corpus {
            footage: &[],
            first_party: &refs,
            claimable: &refs,
        };
        let delta = PersonaDelta {
            facet: Facet::Opinion,
            memory_id: memories[0].id,
            correction_id: None,
            weight: 0.3,
            queued_at: Timestamp::new(0, 0),
            from_holdout: false,
        };
        let deltas = vec![delta.clone(), delta];

        let next =
            distill(Some(&prior), &corpus, &deltas, Timestamp::new(2_000, 0), 2).expect("distil");
        assert!((next.facets.opinions[0].strength - 0.0).abs() < f32::EPSILON);
    }

    /// Ten corrections justify a distillation on their own; fewer wait for the
    /// weekly cadence, because a version bump on noise is one nobody reviews.
    #[test]
    fn the_delta_threshold_and_the_weekly_cadence_both_trigger() {
        let delta = PersonaDelta {
            facet: Facet::Opinion,
            memory_id: MemoryId::new(1, [1u8; 10]),
            correction_id: None,
            weight: 1.0,
            queued_at: Timestamp::new(0, 0),
            from_holdout: false,
        };
        let many: Vec<PersonaDelta> = std::iter::repeat_n(delta.clone(), 10).collect();
        let few: Vec<PersonaDelta> = std::iter::repeat_n(delta, 2).collect();
        let start = Timestamp::new(0, 0);
        let a_day = Timestamp::new(86_400_000, 0);
        let a_week = Timestamp::new(7 * 86_400_000, 0);

        assert!(should_distill(start, a_day, &many, true), "threshold");
        assert!(
            !should_distill(start, a_day, &few, true),
            "too soon, too few"
        );
        assert!(should_distill(start, a_week, &few, true), "weekly");
        assert!(
            !should_distill(start, a_week, &few, false),
            "weekly cadence off"
        );
    }
}
