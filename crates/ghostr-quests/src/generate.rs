//! Choosing what to ask, and committing to the answer before asking.

use chrono::NaiveDate;
use ghostr_core::ids::PersonaVersion;
use ghostr_core::persona::PersonaModel;
use ghostr_core::quest::{Facet, Quest, QuestKind};
use ghostr_core::time::{Rng, Timestamp};
// Re-exported below: a caller cannot build a `QuestContext` without naming this
// type, so it belongs to this crate's surface whether or not the caller has
// `ghostr-llm` in its own manifest.
pub use ghostr_llm::model::CapabilityTier;
use serde::{Deserialize, Serialize};

/// Generates a day's quests.
pub trait QuestGenerator: Send + Sync {
    /// Generates `n` quests.
    ///
    /// Every returned quest must already carry its `answer_commitment` and
    /// `nonce`. The commitment is computed here, before anything can reach a
    /// display path — that ordering is the whole guarantee (SPEC I6).
    ///
    /// # Errors
    ///
    /// Returns [`Error::Llm`](crate::Error::Llm) if the model fails.
    fn generate(&self, ctx: &QuestContext<'_>, n: usize) -> crate::Result<Vec<Quest>>;

    /// Ranks facets by how much a probe would tell us.
    ///
    /// `uncertainty × staleness × coverage_debt × (1 - user_fatigue)`
    /// (SPEC §4.2). Fatigue is in the product because a user who stops answering
    /// is worse than a user who answers fewer.
    fn prioritise(&self, ctx: &QuestContext<'_>) -> Vec<(Facet, f32)>;

    /// How many quests to issue today.
    ///
    /// Default 5, adaptive 3–10 on completion rate.
    fn daily_count(&self, ctx: &QuestContext<'_>) -> usize;
}

/// What a generator gets to look at.
#[derive(Clone, Copy)]
pub struct QuestContext<'a> {
    /// The ghost doing the claiming.
    pub persona: &'a PersonaModel,
    /// Which version that is.
    pub version: PersonaVersion,
    /// The day being generated for.
    pub date: NaiveDate,
    /// Now.
    pub now: Timestamp,
    /// Entropy for nonces and holdout selection.
    ///
    /// A seam, not a convenience: holdout assignment must be reproducible in
    /// tests, or the property that makes the score meaningful cannot be tested.
    pub rng: &'a dyn Rng,
    /// What the local model can be trusted with.
    ///
    /// Drives graceful degradation. Below [`CapabilityTier::Baseline`] the
    /// generator emits fewer mechanical quests rather than bad hard ones
    /// (SPEC Q7).
    pub tier: CapabilityTier,
    /// Recent engagement, for the fatigue term.
    pub engagement: EngagementStats,
    /// The holdout policy in force.
    pub holdout: HoldoutPolicy,
    /// Answers already sitting unanswered on the user's screen.
    ///
    /// A question still open from yesterday and asked again today is the same
    /// question twice, and it reads as the ghost not paying attention. The
    /// caller supplies these because only it can see the open set.
    pub avoid: &'a [String],
    /// Sentences the user actually wrote, for cloze quests.
    ///
    /// Supplied by the caller because a persona carries exemplar *ids* and the
    /// text lives in the store. A cloze's ground truth has to be something the
    /// user really wrote — asking a model to invent the sentence would make the
    /// answer key fiction.
    pub voice_exemplars: &'a [(ghostr_core::ids::MemoryId, String)],
    /// Quests a model wrote, already validated.
    ///
    /// Supplied by the caller for the same reason as `voice_exemplars`: the
    /// thing that produces these lives outside. A model call is I/O, and this
    /// module stays synchronous so its choosing logic remains property-testable
    /// (CLAUDE.md §5) — the composition root owns the runtime, asks the model,
    /// and hands the answers in.
    ///
    /// Empty is the normal case. A build with no model, a model that failed, and
    /// a model that returned nothing usable are the same case here on purpose:
    /// fewer quests of the kinds the ghost can do well, never worse ones of the
    /// kinds it cannot (SPEC Q7).
    pub model_drafts: &'a [ModelDraft],
}

/// A quest a model wrote, after validation.
///
/// The three kinds no amount of string manipulation can produce:
/// [`QuestKind::VoiceProbe`], [`QuestKind::Counterfactual`], and
/// [`QuestKind::Prediction`]. Each needs the prompt itself to be written, which
/// is judgement rather than mechanism.
///
/// Carries no id, no nonce, and no commitment. Those are attached by the same
/// private `finish` path every mechanical draft goes through, so a model-written
/// quest cannot reach a display without a commitment any more than a cloze can
/// (I6).
#[derive(Debug, Clone, PartialEq)]
pub struct ModelDraft {
    /// The written quest.
    pub kind: QuestKind,
    /// Which facet it probes.
    pub facet: Facet,
    /// How hard the ghost thinks it is, in `0.0..=1.0`.
    pub difficulty: f32,
    /// The ghost's own probability the user confirms, in `0.0..=1.0`.
    pub confidence: f32,
    /// The memories it was drawn from.
    ///
    /// Never empty in practice: a claim with no evidence is one the ghost
    /// invented, and [`ModelDraft::is_admissible`] refuses it.
    pub evidence: Vec<ghostr_core::ids::MemoryId>,
}

impl ModelDraft {
    /// Whether this draft may become a quest.
    ///
    /// The boundary where model output stops being trusted. A model that has
    /// just read the user's corpus is an untrusted source (THREAT_MODEL §T7),
    /// and schema validation only proves the *shape* — these are the checks on
    /// the meaning:
    ///
    /// - It must be one of the three kinds a model is for. A model returning a
    ///   `Cloze` would be inventing the answer key to a question about a
    ///   sentence the user wrote, which is the one thing cloze exists to avoid.
    /// - It must cite evidence. A claim with nothing behind it is a
    ///   hallucination, and scoring the user against one is worse than not
    ///   asking.
    /// - Its text must be non-empty, so an empty prompt cannot reach a screen.
    #[must_use]
    pub fn is_admissible(&self) -> bool {
        let right_kind = matches!(
            self.kind,
            QuestKind::VoiceProbe { .. }
                | QuestKind::Counterfactual { .. }
                | QuestKind::Prediction { .. }
        );
        right_kind && !self.evidence.is_empty() && !self.kind.committed_answer().trim().is_empty()
    }
}

impl core::fmt::Debug for QuestContext<'_> {
    /// Prints the scalar context, never the persona and never the RNG.
    ///
    /// `Rng` has no `Debug` bound on purpose: a rendering of an RNG is a
    /// rendering of its seed state, and the seed decides holdout assignment.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("QuestContext")
            .field("version", &self.version)
            .field("date", &self.date)
            .field("tier", &self.tier)
            .field("engagement", &self.engagement)
            .field("holdout", &self.holdout)
            .finish_non_exhaustive()
    }
}

/// How the user has been engaging.
#[derive(Debug, Clone, Copy, PartialEq, Default, Serialize, Deserialize)]
pub struct EngagementStats {
    /// Fraction of issued quests answered in the last 30 days.
    pub completion_rate: f32,
    /// Median seconds to answer.
    pub median_answer_seconds: f32,
    /// Consecutive days with at least one answer.
    pub streak_days: u32,
}

/// How quests are split between training and scoring.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct HoldoutPolicy {
    /// Fraction held out.
    ///
    /// 0.30 in steady state. Higher early on: at 5 quests a day a 30% holdout
    /// needs about 130 days to reach 200 scored quests, past the 60-day
    /// convergence floor. Raising it during the first month costs nothing —
    /// there is little to train on yet — and front-loads the evidence
    /// (SPEC Q8).
    pub fraction: f32,
    /// Fraction that are deliberately wrong. 0.05.
    pub decoy_fraction: f32,
    /// Seconds below which a verdict is flagged as suspiciously fast.
    ///
    /// Flagged in [`IntegritySignals`](ghostr_core::fidelity::IntegritySignals),
    /// never scored differently. Adjusting the score silently would hide the
    /// signal a reader needs in order to discount it.
    pub latency_floor_seconds: f32,
}

impl Default for HoldoutPolicy {
    fn default() -> Self {
        Self {
            fraction: 0.30,
            decoy_fraction: 0.05,
            latency_floor_seconds: 2.0,
        }
    }
}

/// Builds a quest's answer commitment.
///
/// `H_tag(QuestAnswer, quest_id || canonical(answer) || confidence || nonce)`.
///
/// # Errors
///
/// Returns [`Error::Core`](crate::Error::Core) if canonical encoding fails.
pub fn commit_answer(
    quest: &Quest,
    answer: &str,
    confidence: f32,
    nonce: &[u8; 32],
) -> crate::Result<ghostr_core::hash::Hash32> {
    use ghostr_core::canonical::{ratio_to_fixed, to_canonical_cbor};
    use ghostr_core::hash::{Tag, tagged_hash_parts};

    // Canonical, because a commitment that could be recomputed two ways is not
    // a commitment. Confidence goes through fixed point for the same reason the
    // persona version does: canonical CBOR rejects floats, and it is right to —
    // one value must have exactly one encoding.
    let body = to_canonical_cbor(&(answer, ratio_to_fixed(confidence, "confidence")?))?;

    Ok(tagged_hash_parts(
        Tag::QuestAnswer,
        &[quest.id.as_uuid().as_bytes(), &body, nonce],
    ))
}

/// Whether a quest's stored commitment matches a claimed answer.
///
/// The verification side of [`commit_answer`], and what makes the
/// pre-commitment real rather than decorative: without this check the
/// commitment is a value nobody ever compares against (SPEC I6).
///
/// Constant-time on the digest comparison — a timing oracle here would let a
/// caller search for the committed answer one byte at a time.
///
/// # Errors
///
/// Returns [`Error::Core`](crate::Error::Core) if canonical encoding fails.
pub fn verify_commitment(quest: &Quest, answer: &str, confidence: f32) -> crate::Result<bool> {
    let recomputed = commit_answer(quest, answer, confidence, &quest.nonce)?;
    let a = recomputed.as_bytes();
    let b = quest.answer_commitment.as_bytes();

    let mut difference = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        difference |= x ^ y;
    }
    Ok(difference == 0)
}

/// The deterministic generator.
///
/// # What can be asked without a model
///
/// Three of the six quest kinds are mechanical, and they are the three this
/// generator produces:
///
/// - **`Cloze`** — take a sentence the user wrote, remove a span, ask them to
///   fill it. Ground truth is exact and needs nobody's judgement.
/// - **`Preference`** — two options drawn from recorded stances, and the
///   ghost's pick. Cheap, high-signal, low-effort for the user.
/// - **`FactRecall`** — a claim assembled from a persona facet, dated.
///
/// `VoiceProbe` and `Counterfactual` genuinely need a model to *write* the
/// prompt, and `Prediction` needs one to be worth asking. Without a model this
/// generator emits fewer quests of the kinds it can do well rather than bad
/// ones of the kinds it cannot (SPEC Q7).
///
/// # The commitment comes first
///
/// Every quest leaves this function with `answer_commitment` already set. There
/// is no path here that produces a quest without one, which is what makes I6
/// structural rather than a rule somebody has to remember.
#[derive(Debug, Clone, Copy, Default)]
pub struct DeterministicGenerator;

/// The default number of quests a day.
pub const DEFAULT_DAILY: usize = 5;
/// The fewest a fatigued user is asked.
pub const MIN_DAILY: usize = 3;
/// The most an engaged user is asked.
pub const MAX_DAILY: usize = 10;

/// How long a quest stays answerable.
const EXPIRY_HOURS: i64 = 48;

impl QuestGenerator for DeterministicGenerator {
    fn generate(&self, ctx: &QuestContext<'_>, n: usize) -> crate::Result<Vec<Quest>> {
        // Facets in priority order, so a scarce budget starts where a probe
        // would tell us most — but taken one at a time and cycled, not drained.
        // Draining the top facet first issues ten clozes and calls that a day's
        // coverage, and a score with one facet in it cannot say the thing a
        // per-facet breakdown exists to say (SPEC §4.2).
        let mut by_facet: Vec<Vec<Draft>> = self
            .prioritise(ctx)
            .into_iter()
            .map(|(facet, _)| candidates_for(ctx, facet))
            .filter(|drafts| !drafts.is_empty())
            .collect();

        let mut out = Vec::new();
        // Two quests with the same answer in one day is one question asked
        // twice: it doubles the weight of whatever it probes and reads, to the
        // user, as the ghost not paying attention.
        let mut asked: std::collections::BTreeSet<String> = ctx.avoid.iter().cloned().collect();

        while out.len() < n {
            let before = out.len();
            for drafts in &mut by_facet {
                if out.len() >= n {
                    break;
                }
                let Some(position) = drafts
                    .iter()
                    .position(|d| !asked.contains(d.kind.committed_answer()))
                else {
                    // Everything left in this facet repeats something already
                    // asked. Drop it rather than carrying it into every round.
                    drafts.clear();
                    continue;
                };
                let draft = drafts.remove(position);
                asked.insert(draft.kind.committed_answer().to_owned());
                let index = out.len();
                out.push(finish(ctx, draft, index)?);
            }
            // Every facet is exhausted. Fewer quests than asked for is the
            // honest answer; padding would mean asking something twice.
            if out.len() == before {
                break;
            }
        }
        Ok(out)
    }

    fn prioritise(&self, ctx: &QuestContext<'_>) -> Vec<(Facet, f32)> {
        let facets = &ctx.persona.facets;

        // `uncertainty × staleness × coverage_debt × (1 - fatigue)` (SPEC §4.2).
        // Fatigue is inside the product rather than beside it because a user who
        // stops answering is worse than a user who answers fewer: a facet worth
        // probing is not worth probing at the cost of the whole loop.
        let fatigue = (1.0 - ctx.engagement.completion_rate).clamp(0.0, 1.0);
        let mut scored: Vec<(Facet, f32)> = [
            (Facet::Voice, evidence_count(facets.voice.exemplars.len())),
            (Facet::Opinion, evidence_count(facets.opinions.len())),
            (
                Facet::Relationship,
                evidence_count(facets.relationships.len()),
            ),
            (Facet::Routine, evidence_count(facets.routines.len())),
            (Facet::Lore, evidence_count(facets.lore.len())),
        ]
        .into_iter()
        .map(|(facet, supported)| {
            // A facet with little behind it is the one a probe tells us most
            // about — but only if there is anything to probe at all, which
            // `candidates_for` decides.
            let uncertainty = 1.0 - supported;
            (facet, uncertainty * (1.0 - fatigue * 0.5))
        })
        .collect();

        // Ties break on the facet's own order so generation is reproducible: a
        // quest set that varied between runs over the same persona would make
        // the day's issue non-deterministic under a fixed seed.
        scored.sort_by(|a, b| {
            b.1.partial_cmp(&a.1)
                .unwrap_or(core::cmp::Ordering::Equal)
                .then_with(|| format!("{:?}", a.0).cmp(&format!("{:?}", b.0)))
        });
        scored
    }

    fn daily_count(&self, ctx: &QuestContext<'_>) -> usize {
        let rate = ctx.engagement.completion_rate.clamp(0.0, 1.0);
        // Adaptive on completion rate: someone answering everything gets more,
        // someone ignoring them gets fewer rather than the same pile again.
        let scaled = MIN_DAILY as f32 + rate * (MAX_DAILY - MIN_DAILY) as f32;
        let count = scaled.round() as usize;
        count.clamp(MIN_DAILY, MAX_DAILY)
    }
}

/// How well-supported a facet is, on a `0.0..=1.0` scale.
///
/// Saturating rather than linear: the difference between one stance and five is
/// large, the difference between fifty and sixty is not.
fn evidence_count(n: usize) -> f32 {
    (n as f32 / (n as f32 + 5.0)).clamp(0.0, 1.0)
}

/// A quest before its identity and commitment are attached.
///
/// Carries no answer field. The answer is
/// [`QuestKind::committed_answer`](ghostr_core::quest::QuestKind::committed_answer),
/// read back off the kind itself — a separate field could disagree with the
/// claim, and a commitment over an answer the quest does not state is a
/// commitment nobody can check (I6).
struct Draft {
    kind: QuestKind,
    facet: Facet,
    difficulty: f32,
    confidence: f32,
    evidence: Vec<ghostr_core::ids::MemoryId>,
}

/// The quests a facet can support.
///
/// Model-written drafts for this facet come first, then the mechanical ones.
/// Order matters because the budget is finite: a `VoiceProbe` and a `Cloze` both
/// probe the voice, and the probe is the harder, more informative question — so
/// when only one fits, it should be the one asked.
fn candidates_for(ctx: &QuestContext<'_>, facet: Facet) -> Vec<Draft> {
    let mut drafts: Vec<Draft> = ctx
        .model_drafts
        .iter()
        .filter(|d| d.facet == facet && d.is_admissible())
        .cloned()
        .map(|d| Draft {
            kind: d.kind,
            facet: d.facet,
            difficulty: d.difficulty,
            confidence: d.confidence,
            evidence: d.evidence,
        })
        .collect();
    drafts.extend(mechanical_for(ctx, facet));
    drafts
}

/// The quests a facet can support with no model at all.
fn mechanical_for(ctx: &QuestContext<'_>, facet: Facet) -> Vec<Draft> {
    let facets = &ctx.persona.facets;
    match facet {
        Facet::Opinion => facets
            .opinions
            .iter()
            .filter(|s| !s.evidence.is_empty())
            .map(|stance| Draft {
                kind: QuestKind::Preference {
                    a: stance.position.clone(),
                    b: format!("not {}", stance.position),
                    ghost_choice: ghostr_core::quest::Choice::A,
                },
                facet,
                // A stance the corpus states plainly is an easy question; a
                // weakly-held one is a hard one, and the score weights it so.
                difficulty: 1.0 - stance.strength.clamp(0.0, 1.0),
                confidence: stance.strength.clamp(0.0, 1.0),
                evidence: stance.evidence.clone(),
            })
            .collect(),

        Facet::Routine => facets
            .routines
            .iter()
            .filter(|r| !r.evidence.is_empty())
            .map(|routine| Draft {
                kind: QuestKind::FactRecall {
                    claim: format!("you keep coming back to: {}", routine.pattern),
                    as_of: ctx.date,
                },
                facet,
                difficulty: 1.0 - routine.confidence.clamp(0.0, 1.0),
                confidence: routine.confidence.clamp(0.0, 1.0),
                evidence: routine.evidence.clone(),
            })
            .collect(),

        Facet::Lore => facets
            .lore
            .iter()
            .filter(|l| !l.evidence.is_empty())
            .map(|fact| Draft {
                kind: QuestKind::FactRecall {
                    claim: fact.statement.clone(),
                    as_of: ctx.date,
                },
                facet,
                difficulty: 1.0 - fact.confidence.clamp(0.0, 1.0),
                confidence: fact.confidence.clamp(0.0, 1.0),
                evidence: fact.evidence.clone(),
            })
            .collect(),

        Facet::Voice => ctx
            .voice_exemplars
            .iter()
            .filter_map(|(id, text)| {
                let kind = cloze_from(text, *id)?;
                Some(Draft {
                    kind,
                    facet,
                    // A cloze over the user's own sentence has exact ground
                    // truth, so it is the easiest thing the ghost is asked and
                    // the score weights it lowest.
                    difficulty: 0.3,
                    confidence: 0.6,
                    evidence: vec![*id],
                })
            })
            .collect(),

        // Relationship quests name a person, and naming one well needs the role
        // a model supplies — so there is nothing mechanical here. `candidates_for`
        // still serves this facet when a model wrote something for it.
        Facet::Relationship => Vec::new(),
        _ => Vec::new(),
    }
}

/// Builds a cloze from a sentence the user actually wrote.
///
/// Exposed because a persona carries exemplar *ids* and the text lives in the
/// store, so the engine assembles this rather than the generator reaching for a
/// database it has no business holding.
///
/// Returns `None` when the sentence is too short to remove a span from without
/// making the question unanswerable.
#[must_use]
pub fn cloze_from(text: &str, memory: ghostr_core::ids::MemoryId) -> Option<QuestKind> {
    use ghostr_core::memory::Span;

    let _ = memory;
    let sentence = pick_sentence(text)?;
    let (offset, word) = pick_word(sentence)?;

    // Offsets are into the sentence, and the sentence is what is shown. A span
    // measured against the whole note would point somewhere else entirely.
    Some(QuestKind::Cloze {
        context: sentence.to_owned(),
        redacted: Span {
            start: u32::try_from(offset).ok()?,
            end: u32::try_from(offset + word.len()).ok()?,
        },
        ghost_completion: word.to_owned(),
    })
}

/// The sentence a cloze is built from.
///
/// One sentence, not the whole note. A gap in the middle of three paragraphs is
/// not a question anyone can answer — the surrounding text is noise, and the
/// user is being asked to recall which of forty words was removed.
///
/// Markdown structure is skipped: a list item or a heading is not a sentence
/// the user *wrote* so much as one they formatted, and quizzing someone on
/// their own checkbox tests nothing about their voice.
fn pick_sentence(text: &str) -> Option<&str> {
    text.lines()
        .map(str::trim)
        .filter(|line| {
            !line.is_empty()
                && !line.starts_with('-')
                && !line.starts_with('*')
                && !line.starts_with('#')
                && !line.starts_with('>')
                && !line.starts_with("- [")
        })
        .flat_map(|line| line.split_terminator(['.', '!', '?']))
        .map(str::trim)
        // Deterministic: the longest qualifying sentence, ties broken by order.
        // The same exemplar must produce the same question, or a re-run would
        // issue a different quest under the same persona version.
        .filter(|s| s.split_whitespace().count() >= MIN_CLOZE_WORDS)
        .max_by_key(|s| s.split_whitespace().count())
}

/// The fewest words a sentence needs before a gap leaves anything to reason from.
const MIN_CLOZE_WORDS: usize = 6;

/// The shortest word worth asking about.
const MIN_CLOZE_WORD_LEN: usize = 4;

/// Words that carry no voice, so removing one asks nothing about the person.
const STOPWORDS: &[&str] = &[
    "about", "after", "again", "been", "before", "being", "some", "such", "than", "that", "them",
    "then", "there", "these", "they", "this", "those", "very", "were", "what", "when", "which",
    "while", "with", "would", "your", "from", "have", "just", "like", "more", "much", "only",
    "over", "into", "will", "still",
];

/// Picks the word to remove, and its byte offset in the sentence.
///
/// Returns `None` when nothing in the sentence is worth asking about. Fewer
/// quests of the kinds it can do well beats bad ones of the kinds it cannot
/// (SPEC Q7).
fn pick_word(sentence: &str) -> Option<(usize, &str)> {
    let mut candidates: Vec<(usize, &str)> = Vec::new();
    let mut offset = 0usize;

    for word in sentence.split_whitespace() {
        // Walked rather than searched. `str::find` returns the *first* match,
        // so a word appearing twice would put the gap on the wrong occurrence —
        // and the ghost's committed answer would then be a word the user can
        // still see.
        let at = sentence[offset..].find(word)? + offset;
        offset = at + word.len();

        let bare = word.trim_matches(|c: char| !c.is_alphanumeric());
        if bare.len() < MIN_CLOZE_WORD_LEN {
            continue;
        }
        let lowered = bare.to_lowercase();
        if STOPWORDS.contains(&lowered.as_str()) {
            continue;
        }
        // A name or handle identifies someone rather than testing voice, and a
        // gap where a person's name was is a quiz about other people.
        if word.starts_with('@') || word.starts_with('#') {
            continue;
        }
        // Must be unique in the sentence, or the gap is ambiguous: the user
        // could fill it correctly with a word the ghost did not commit to.
        if sentence.matches(bare).count() != 1 {
            continue;
        }
        let bare_at = at + word.find(bare)?;
        candidates.push((bare_at, bare));
    }

    // The middle candidate, so there is context on both sides.
    candidates.get(candidates.len() / 2).copied()
}

/// Attaches identity, holdout status, and the commitment.
///
/// The commitment is computed here and the quest is returned with it already
/// set. There is no intermediate value a caller could display.
fn finish(ctx: &QuestContext<'_>, draft: Draft, index: usize) -> crate::Result<Quest> {
    use ghostr_core::ids::QuestId;
    use ghostr_core::quest::QuestStatus;

    let mut random = [0u8; 10];
    ctx.rng.fill(&mut random);
    let mut nonce = [0u8; 32];
    ctx.rng.fill(&mut nonce);

    let holdout = draws_below(ctx.rng, ctx.holdout.fraction);
    // A decoy is never held out: it is a deliberately wrong claim, so scoring
    // against it would measure the ghost on a question it was set up to fail.
    // The decoy rate is an integrity signal, not part of the score (SPEC §4.4).
    let decoy = !holdout && draws_below(ctx.rng, ctx.holdout.decoy_fraction);

    let mut quest = Quest {
        id: QuestId::new(
            ctx.now
                .utc_millis()
                .unsigned_abs()
                .saturating_add(index as u64),
            random,
        ),
        issued_for: ctx.date,
        issued_at: ctx.now,
        persona_version: ctx.version,
        kind: draft.kind,
        facet: draft.facet,
        difficulty: draft.difficulty.clamp(0.0, 1.0),
        evidence: draft.evidence,
        confidence: draft.confidence.clamp(0.0, 1.0),
        // Replaced immediately below, before this value can escape.
        answer_commitment: ghostr_core::hash::Hash32::zero(),
        nonce,
        holdout,
        decoy,
        expires_at: Timestamp::new(
            ctx.now
                .utc_millis()
                .saturating_add(EXPIRY_HOURS * 3_600_000),
            ctx.now.offset_seconds(),
        ),
        status: QuestStatus::Open,
        verdict: None,
    };

    let answer = quest.kind.committed_answer().to_owned();
    quest.answer_commitment = commit_answer(&quest, &answer, quest.confidence, &nonce)?;
    Ok(quest)
}

/// A reproducible Bernoulli draw.
///
/// Reads from the injected RNG rather than a thread-local, because holdout
/// assignment must be reproducible in a test — the property that makes the
/// score meaningful cannot be tested otherwise.
fn draws_below(rng: &dyn Rng, probability: f32) -> bool {
    let mut buf = [0u8; 4];
    rng.fill(&mut buf);
    let draw = f64::from(u32::from_le_bytes(buf)) / f64::from(u32::MAX);
    draw < f64::from(probability.clamp(0.0, 1.0))
}

#[cfg(test)]
mod tests {
    use ghostr_core::ids::MemoryId;
    use ghostr_core::persona::{
        Facets, LoreFact, PersonaModel, PunctuationHabits, Register, Routine, Stance, SyntaxStats,
        VoiceProfile,
    };

    use super::*;

    /// SplitMix64, matching `ghostr-testkit`. Duplicated rather than depending
    /// on testkit, which depends on this crate's siblings — a dev-dependency
    /// cycle through `ghostr-llm` is avoidable here for eight lines.
    struct SeededRng(std::sync::Mutex<u64>);

    impl SeededRng {
        fn new(seed: u64) -> Self {
            Self(std::sync::Mutex::new(seed))
        }
    }

    impl Rng for SeededRng {
        fn fill(&self, buf: &mut [u8]) {
            let mut state = self
                .0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            for chunk in buf.chunks_mut(8) {
                *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
                let mut z = *state;
                z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
                z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
                z ^= z >> 31;
                let bytes = z.to_le_bytes();
                chunk.copy_from_slice(&bytes[..chunk.len()]);
            }
        }
    }

    fn persona() -> PersonaModel {
        PersonaModel {
            version: PersonaVersion::genesis(),
            parent: None,
            created_at: Timestamp::new(0, 0),
            facets: Facets {
                voice: VoiceProfile {
                    register: Register {
                        formality: 0.5,
                        warmth: 0.5,
                        hedging: 0.2,
                        profanity: 0.0,
                    },
                    lexicon: Vec::new(),
                    syntax: SyntaxStats {
                        mean_sentence_words: 12.0,
                        sentence_words_stddev: 3.0,
                        mean_clause_depth: 1.0,
                        fragment_rate: 0.1,
                    },
                    punctuation: PunctuationHabits {
                        em_dash_rate: 0.0,
                        lowercase_start_rate: 0.0,
                        emoji_rate: 0.0,
                        ellipsis_rate: 0.0,
                        unterminated_rate: 0.0,
                    },
                    exemplars: vec![MemoryId::new(1, [1u8; 10])],
                },
                opinions: vec![Stance {
                    topic: "remote work".to_owned(),
                    position: "prefers it".to_owned(),
                    strength: 0.8,
                    stability: 0.7,
                    evidence: vec![MemoryId::new(1, [1u8; 10])],
                    last_seen: Timestamp::new(0, 0),
                    contradicted_by: Vec::new(),
                }],
                relationships: Vec::new(),
                routines: vec![Routine {
                    pattern: "the weekly review".to_owned(),
                    schedule: "came back 5 times in 30 day(s)".to_owned(),
                    confidence: 0.6,
                    evidence: vec![MemoryId::new(2, [2u8; 10])],
                }],
                boundaries: Vec::new(),
                lore: vec![LoreFact {
                    statement: "works on a parser".to_owned(),
                    confidence: 0.9,
                    evidence: vec![MemoryId::new(3, [3u8; 10])],
                }],
            },
            derived_from: Vec::new(),
            diff: None,
        }
    }

    fn context<'a>(model: &'a PersonaModel, rng: &'a dyn Rng) -> QuestContext<'a> {
        context_with(model, rng, &[])
    }

    fn context_with<'a>(
        model: &'a PersonaModel,
        rng: &'a dyn Rng,
        voice_exemplars: &'a [(MemoryId, String)],
    ) -> QuestContext<'a> {
        context_full(model, rng, voice_exemplars, &[])
    }

    fn context_full<'a>(
        model: &'a PersonaModel,
        rng: &'a dyn Rng,
        voice_exemplars: &'a [(MemoryId, String)],
        model_drafts: &'a [ModelDraft],
    ) -> QuestContext<'a> {
        QuestContext {
            persona: model,
            version: model.version,
            date: chrono::NaiveDate::from_ymd_opt(2026, 1, 5).unwrap_or_default(),
            now: Timestamp::new(1_767_000_000_000, 0),
            rng,
            tier: CapabilityTier::Baseline,
            engagement: EngagementStats {
                completion_rate: 0.8,
                median_answer_seconds: 15.0,
                streak_days: 4,
            },
            holdout: HoldoutPolicy::default(),
            avoid: &[],
            voice_exemplars,
            model_drafts,
        }
    }

    /// SPEC I6, and the property the whole quest loop rests on. There is no
    /// path out of `generate` that yields a quest without a commitment, so a
    /// future client cannot peek at the user's answer and adjust the ghost's
    /// before scoring.
    #[test]
    fn every_generated_quest_arrives_already_committed() {
        let model = persona();
        let rng = SeededRng::new(42);
        let quests = DeterministicGenerator
            .generate(&context(&model, &rng), 3)
            .expect("generate");

        assert!(!quests.is_empty());
        for quest in &quests {
            assert_ne!(
                quest.answer_commitment,
                ghostr_core::hash::Hash32::zero(),
                "a quest escaped without a commitment"
            );
            assert_ne!(quest.nonce, [0u8; 32], "and without a blinding nonce");
        }
    }

    /// The verification side. Without it the commitment is a value nobody ever
    /// compares against, which is decoration rather than a guarantee.
    #[test]
    fn a_commitment_verifies_against_the_answer_it_was_made_for() {
        let model = persona();
        let rng = SeededRng::new(7);
        let ctx = context(&model, &rng);
        let quests = DeterministicGenerator.generate(&ctx, 5).expect("generate");

        // The opinion quest commits to the stance's position.
        let opinion = quests
            .iter()
            .find(|q| q.facet == Facet::Opinion)
            .expect("an opinion quest");
        assert!(
            verify_commitment(opinion, "prefers it", opinion.confidence).expect("verify"),
            "the committed answer did not verify"
        );
    }

    /// Every quest must be verifiable from itself alone. The store keeps only
    /// the digest, so if the answer were not recoverable off the kind there
    /// would be nothing to verify against at verdict time (I6).
    #[test]
    fn every_quest_verifies_against_its_own_kind() {
        let model = persona();
        let rng = SeededRng::new(11);
        let quests = DeterministicGenerator
            .generate(&context(&model, &rng), 8)
            .expect("generate");
        assert!(!quests.is_empty());
        for quest in &quests {
            assert!(
                verify_commitment(quest, quest.kind.committed_answer(), quest.confidence)
                    .expect("verify"),
                "a quest could not reproduce its own commitment"
            );
        }
    }

    /// Changing the answer breaks the commitment — which is the entire point.
    #[test]
    fn a_different_answer_fails_the_commitment() {
        let model = persona();
        let rng = SeededRng::new(7);
        let ctx = context(&model, &rng);
        let quests = DeterministicGenerator.generate(&ctx, 5).expect("generate");
        let quest = &quests[0];

        assert!(!verify_commitment(quest, "something else entirely", quest.confidence).expect("v"));
    }

    /// And so does changing the confidence. Confidence is inside the preimage
    /// because calibration is only measurable if the ghost cannot revise what
    /// it claimed after seeing the outcome (SPEC Q17).
    #[test]
    fn a_revised_confidence_fails_the_commitment() {
        let model = persona();
        let rng = SeededRng::new(7);
        let ctx = context(&model, &rng);
        let quests = DeterministicGenerator.generate(&ctx, 5).expect("generate");
        let quest = quests
            .iter()
            .find(|q| q.facet == Facet::Opinion)
            .expect("an opinion quest");

        let answer = "prefers it";
        assert!(verify_commitment(quest, answer, quest.confidence).expect("v"));
        assert!(!verify_commitment(quest, answer, 0.05).expect("v"));
    }

    /// One question asked twice doubles the weight of whatever it probes, and
    /// reads to the user as the ghost not paying attention.
    #[test]
    fn a_day_never_asks_the_same_thing_twice() {
        let model = persona();
        let rng = SeededRng::new(5);
        // Three exemplars, two of which say exactly the same thing.
        let repeated = "I spent the whole afternoon wrestling with the parser again".to_owned();
        let exemplars = vec![
            (MemoryId::new(1, [1u8; 10]), repeated.clone()),
            (MemoryId::new(2, [2u8; 10]), repeated),
            (
                MemoryId::new(3, [3u8; 10]),
                "The train was late so I read on the platform instead".to_owned(),
            ),
        ];

        let quests = DeterministicGenerator
            .generate(&context_with(&model, &rng, &exemplars), 10)
            .expect("generate");
        let answers: std::collections::BTreeSet<&str> =
            quests.iter().map(|q| q.kind.committed_answer()).collect();
        assert_eq!(
            answers.len(),
            quests.len(),
            "the same question was issued more than once"
        );
    }

    /// Two quests must not share a nonce, or one commitment could be replayed
    /// against another quest.
    #[test]
    fn nonces_are_unique_across_a_day() {
        let model = persona();
        let rng = SeededRng::new(1);
        let quests = DeterministicGenerator
            .generate(&context(&model, &rng), 3)
            .expect("generate");
        let nonces: std::collections::BTreeSet<[u8; 32]> = quests.iter().map(|q| q.nonce).collect();
        assert_eq!(nonces.len(), quests.len());
    }

    /// Holdout assignment must be reproducible under a fixed seed, or the
    /// property that makes the score meaningful cannot be tested at all.
    #[test]
    fn generation_is_reproducible_under_a_fixed_seed() {
        let model = persona();
        let first = DeterministicGenerator
            .generate(&context(&model, &SeededRng::new(99)), 3)
            .expect("a");
        let second = DeterministicGenerator
            .generate(&context(&model, &SeededRng::new(99)), 3)
            .expect("b");

        for (a, b) in first.iter().zip(second.iter()) {
            assert_eq!(a.nonce, b.nonce);
            assert_eq!(a.holdout, b.holdout);
            assert_eq!(a.decoy, b.decoy);
            assert_eq!(a.answer_commitment, b.answer_commitment);
        }
    }

    /// A decoy is a deliberately wrong claim, so scoring against it would
    /// measure the ghost on a question it was set up to fail. The two flags are
    /// mutually exclusive by construction.
    #[test]
    fn a_quest_is_never_both_held_out_and_a_decoy() {
        let model = persona();
        for seed in 0..40 {
            let rng = SeededRng::new(seed);
            for quest in DeterministicGenerator
                .generate(&context(&model, &rng), 3)
                .expect("generate")
            {
                assert!(!(quest.holdout && quest.decoy));
            }
        }
    }

    /// Over many draws the holdout rate should sit near the configured
    /// fraction. Not exact — it is a Bernoulli draw — but a rate of zero or one
    /// would mean the policy is not being applied at all.
    #[test]
    fn the_holdout_rate_tracks_the_policy() {
        let model = persona();
        let mut held = 0;
        let mut total = 0;
        for seed in 0..300 {
            let rng = SeededRng::new(seed);
            for quest in DeterministicGenerator
                .generate(&context(&model, &rng), 3)
                .expect("generate")
            {
                total += 1;
                held += usize::from(quest.holdout);
            }
        }
        let rate = held as f32 / total as f32;
        assert!(
            (0.2..0.4).contains(&rate),
            "holdout rate {rate} is nowhere near the configured 0.30"
        );
    }

    /// A user who stops answering is worse than a user who answers fewer, so
    /// fatigue reduces the count rather than the ghost pressing on.
    #[test]
    fn a_fatigued_user_is_asked_fewer_questions() {
        let model = persona();
        let rng = SeededRng::new(1);
        let mut engaged = context(&model, &rng);
        engaged.engagement.completion_rate = 1.0;
        let mut fatigued = context(&model, &rng);
        fatigued.engagement.completion_rate = 0.0;

        assert!(
            DeterministicGenerator.daily_count(&engaged)
                > DeterministicGenerator.daily_count(&fatigued)
        );
        assert_eq!(DeterministicGenerator.daily_count(&fatigued), MIN_DAILY);
        assert_eq!(DeterministicGenerator.daily_count(&engaged), MAX_DAILY);
    }

    /// A facet with little behind it is the one a probe tells us most about.
    #[test]
    fn a_thin_facet_is_prioritised_over_a_well_supported_one() {
        let mut model = persona();
        for n in 0..20u8 {
            model.facets.lore.push(LoreFact {
                statement: format!("fact {n}"),
                confidence: 0.9,
                evidence: vec![MemoryId::new(u64::from(n) + 10, [n; 10])],
            });
        }
        let rng = SeededRng::new(1);
        let ranked = DeterministicGenerator.prioritise(&context(&model, &rng));

        let lore = ranked
            .iter()
            .position(|(f, _)| *f == Facet::Lore)
            .expect("lore");
        let routine = ranked
            .iter()
            .position(|(f, _)| *f == Facet::Routine)
            .expect("routine");
        assert!(routine < lore, "the thin facet should rank higher");
    }

    /// Without a model, the kinds that need one are absent rather than badly
    /// approximated (SPEC Q7).
    #[test]
    fn only_the_mechanical_kinds_are_generated_without_a_model() {
        let model = persona();
        let rng = SeededRng::new(3);
        let quests = DeterministicGenerator
            .generate(&context(&model, &rng), 10)
            .expect("generate");

        for quest in &quests {
            assert!(
                matches!(
                    quest.kind,
                    QuestKind::Preference { .. }
                        | QuestKind::FactRecall { .. }
                        | QuestKind::Cloze { .. }
                ),
                "generated a kind that needs a model: {:?}",
                quest.kind
            );
        }
    }

    /// A claim with nothing behind it is a hallucination, and the same evidence
    /// rule that governs footage governs quests.
    #[test]
    fn every_generated_quest_cites_evidence() {
        let model = persona();
        let rng = SeededRng::new(5);
        for quest in DeterministicGenerator
            .generate(&context(&model, &rng), 10)
            .expect("generate")
        {
            assert!(!quest.evidence.is_empty(), "{:?} cited nothing", quest.kind);
        }
    }

    /// An empty persona produces no quests rather than invented ones.
    #[test]
    fn an_empty_persona_generates_nothing() {
        let mut model = persona();
        model.facets.opinions.clear();
        model.facets.routines.clear();
        model.facets.lore.clear();

        let rng = SeededRng::new(1);
        assert!(
            DeterministicGenerator
                .generate(&context(&model, &rng), 5)
                .expect("generate")
                .is_empty()
        );
    }

    /// A persona carries exemplar ids; the sentences come from the caller. With
    /// none supplied the generator asks no voice questions rather than inventing
    /// a sentence to quiz the user on.
    #[test]
    fn voice_quests_appear_only_once_exemplar_text_is_supplied() {
        let model = persona();
        let rng = SeededRng::new(3);
        assert!(
            !DeterministicGenerator
                .generate(&context(&model, &rng), 8)
                .expect("generate")
                .iter()
                .any(|q| q.facet == Facet::Voice)
        );

        let exemplars = vec![(
            MemoryId::new(1, [1u8; 10]),
            "I spent the whole afternoon wrestling with the parser again".to_owned(),
        )];
        let rng = SeededRng::new(3);
        let quests = DeterministicGenerator
            .generate(&context_with(&model, &rng, &exemplars), 8)
            .expect("generate");
        let voice = quests
            .iter()
            .find(|q| q.facet == Facet::Voice)
            .expect("a voice quest");
        assert!(matches!(voice.kind, QuestKind::Cloze { .. }));
        assert!(
            verify_commitment(voice, voice.kind.committed_answer(), voice.confidence)
                .expect("verify")
        );
    }

    /// Ground truth for a cloze is something the user actually wrote, so the
    /// span has to land on the real word.
    #[test]
    fn a_cloze_redacts_a_real_span_of_the_sentence() {
        let text = "I spent the whole afternoon wrestling with the parser again";
        let kind = cloze_from(text, MemoryId::new(1, [1u8; 10])).expect("long enough");

        let QuestKind::Cloze {
            context, redacted, ..
        } = &kind
        else {
            panic!("expected a cloze");
        };
        assert_eq!(context, text);
        let span = &context[redacted.start as usize..redacted.end as usize];
        assert_eq!(span, kind.committed_answer());
    }

    /// A gap in the middle of three paragraphs is not a question anyone can
    /// answer. One sentence, so the context is context rather than noise.
    #[test]
    fn a_cloze_is_built_from_one_sentence_not_a_whole_note() {
        let note = "Day 01. Shipped a bit more of the parser and felt alright about it.\n\n\
                    Coffee with @nan about the lease. She thinks it is fine.\n\n\
                    - [ ] groceries\n- [x] groceries\n";
        let kind = cloze_from(note, MemoryId::new(1, [1u8; 10])).expect("a sentence");
        let QuestKind::Cloze { context, .. } = &kind else {
            panic!("expected a cloze");
        };
        assert!(
            !context.contains('\n'),
            "the whole note leaked in: {context}"
        );
        assert!(
            !context.contains("groceries"),
            "a checkbox is not a sentence"
        );
        assert!(context.split_whitespace().count() >= 6);
    }

    /// The span and the committed answer have to describe the same word. A
    /// search for the first match would put the gap on the wrong occurrence,
    /// and the answer would then be a word still visible on screen.
    #[test]
    fn a_repeated_word_does_not_move_the_gap() {
        let text = "the parser broke and then the parser worked and I moved on";
        if let Some(kind) = cloze_from(text, MemoryId::new(1, [1u8; 10])) {
            let QuestKind::Cloze {
                context, redacted, ..
            } = &kind
            else {
                panic!("expected a cloze");
            };
            let span = &context[redacted.start as usize..redacted.end as usize];
            assert_eq!(span, kind.committed_answer());
            assert_eq!(
                context.matches(kind.committed_answer()).count(),
                1,
                "an ambiguous gap can be filled with a word the ghost did not commit to"
            );
        }
    }

    /// Removing "with" or "about" asks nothing about the person, and a gap
    /// where a name was is a quiz about somebody else.
    #[test]
    fn a_cloze_does_not_ask_about_filler_or_names() {
        let text = "I went with @nan about the lease and it was fine after all that";
        if let Some(kind) = cloze_from(text, MemoryId::new(1, [1u8; 10])) {
            let answer = kind.committed_answer();
            assert!(!answer.starts_with('@'));
            assert!(answer.len() >= 4, "{answer}");
            assert!(!["with", "about", "that", "after"].contains(&answer));
        }
    }

    /// Fewer quests of the kinds it can do well beats bad ones of the kinds it
    /// cannot (SPEC Q7).
    #[test]
    fn a_note_with_nothing_worth_asking_produces_no_cloze() {
        assert!(cloze_from("- [ ] milk\n- [x] eggs\n", MemoryId::new(1, [1u8; 10])).is_none());
        assert!(cloze_from("# heading only\n", MemoryId::new(1, [1u8; 10])).is_none());
        assert!(cloze_from("too short", MemoryId::new(1, [1u8; 10])).is_none());
    }

    #[test]
    fn a_sentence_too_short_to_redact_produces_no_cloze() {
        assert!(cloze_from("too short", MemoryId::new(1, [1u8; 10])).is_none());
    }

    /// The same exemplar must produce the same question, or a re-run would
    /// issue a different quest under the same persona version.
    #[test]
    fn a_cloze_is_deterministic() {
        let text = "I spent the whole afternoon wrestling with the parser again";
        let id = MemoryId::new(1, [1u8; 10]);
        assert_eq!(cloze_from(text, id), cloze_from(text, id));
    }

    fn draft_evidence() -> Vec<MemoryId> {
        vec![MemoryId::new(1, [1u8; 10])]
    }

    fn probe(kind: QuestKind) -> ModelDraft {
        ModelDraft {
            kind,
            facet: Facet::Voice,
            difficulty: 0.5,
            confidence: 0.6,
            evidence: draft_evidence(),
        }
    }

    #[test]
    fn the_three_model_kinds_are_admissible() {
        for kind in [
            QuestKind::VoiceProbe {
                prompt: "how would you turn down a meeting?".to_owned(),
                ghost_answer: "briefly, and without apologising".to_owned(),
            },
            QuestKind::Counterfactual {
                scenario: "your flight is cancelled overnight".to_owned(),
                ghost_answer: "book the next one before calling anyone".to_owned(),
            },
            QuestKind::Prediction {
                claim: "you will skip the run tomorrow".to_owned(),
                horizon: chrono::NaiveDate::from_ymd_opt(2026, 1, 6).unwrap_or_default(),
            },
        ] {
            assert!(probe(kind).is_admissible());
        }
    }

    #[test]
    fn a_model_may_not_write_the_mechanical_kinds() {
        // A model returning a `Cloze` would be inventing the answer key to a
        // question about a sentence the user wrote — the one thing cloze exists
        // to avoid. `Preference` and `FactRecall` are drawn from recorded
        // facets, so a model-written one cites evidence it did not derive from.
        let mechanical = [
            QuestKind::Cloze {
                context: "I walked to the river".to_owned(),
                redacted: ghostr_core::memory::Span { start: 2, end: 8 },
                ghost_completion: "walked".to_owned(),
            },
            QuestKind::Preference {
                a: "tea".to_owned(),
                b: "coffee".to_owned(),
                ghost_choice: ghostr_core::quest::Choice::A,
            },
            QuestKind::FactRecall {
                claim: "you went to the market".to_owned(),
                as_of: chrono::NaiveDate::from_ymd_opt(2026, 1, 5).unwrap_or_default(),
            },
        ];
        for kind in mechanical {
            let label = kind.variant_name();
            assert!(!probe(kind).is_admissible(), "{label} should be refused");
        }
    }

    #[test]
    fn a_claim_with_no_evidence_is_refused() {
        // A quest citing nothing is one the ghost invented. Scoring the user
        // against it measures the model's imagination, not the ghost's fidelity.
        let mut draft = probe(QuestKind::VoiceProbe {
            prompt: "what would you say?".to_owned(),
            ghost_answer: "something".to_owned(),
        });
        draft.evidence.clear();
        assert!(!draft.is_admissible());
    }

    #[test]
    fn an_empty_answer_is_refused() {
        // The ghost commits to its answer before the user sees the question
        // (I6). An empty commitment is a commitment to nothing.
        for answer in ["", "   ", "\n\t"] {
            let draft = probe(QuestKind::VoiceProbe {
                prompt: "how would you put it?".to_owned(),
                ghost_answer: answer.to_owned(),
            });
            assert!(!draft.is_admissible(), "{answer:?} should be refused");
        }
    }

    #[test]
    fn an_inadmissible_draft_never_becomes_a_quest() {
        // The gate is in `candidates_for`, not only on the type. A draft that
        // passes the type and fails the gate must not reach `finish`.
        let model = persona();
        let rng = SeededRng::new(4);
        let bad = vec![ModelDraft {
            // No evidence: inadmissible.
            evidence: Vec::new(),
            ..probe(QuestKind::VoiceProbe {
                prompt: "invented from nothing".to_owned(),
                ghost_answer: "also invented".to_owned(),
            })
        }];
        let ctx = context_full(&model, &rng, &[], &bad);
        let quests = DeterministicGenerator.generate(&ctx, 10).expect("generate");

        assert!(
            !quests
                .iter()
                .any(|q| matches!(q.kind, QuestKind::VoiceProbe { .. })),
            "an inadmissible draft reached a quest"
        );
    }

    #[test]
    fn a_model_draft_is_committed_to_like_any_other() {
        // I6 is structural: model-written quests go through the same `finish`
        // path, so they arrive with a commitment or they do not arrive.
        let model = persona();
        let rng = SeededRng::new(9);
        let drafts = vec![probe(QuestKind::VoiceProbe {
            prompt: "how would you decline?".to_owned(),
            ghost_answer: "briefly".to_owned(),
        })];
        let ctx = context_full(&model, &rng, &[], &drafts);
        let quests = DeterministicGenerator.generate(&ctx, 5).expect("generate");

        let probe_quest = quests
            .iter()
            .find(|q| matches!(q.kind, QuestKind::VoiceProbe { .. }))
            .expect("the voice probe was issued");
        assert_ne!(
            probe_quest.answer_commitment,
            ghostr_core::hash::Hash32::zero()
        );
        assert!(verify_commitment(probe_quest, "briefly", probe_quest.confidence).expect("verify"));
    }

    #[test]
    fn a_model_draft_outranks_a_cloze_within_its_facet() {
        // Both probe the voice; the probe is the harder, more informative
        // question, so when the budget only reaches one of them it should be the
        // one asked. Tested on `candidates_for` rather than on `generate`,
        // because that is where the claim actually lives — across facets the
        // order is `prioritise`'s to decide, not this rule's.
        let model = persona();
        let rng = SeededRng::new(3);
        let exemplars = vec![(
            MemoryId::new(1, [1u8; 10]),
            "I walked to the river before work and left the phone at home.".to_owned(),
        )];
        let drafts = vec![probe(QuestKind::VoiceProbe {
            prompt: "how would you describe your morning?".to_owned(),
            ghost_answer: "flatly, and shorter than expected".to_owned(),
        })];
        let ctx = context_full(&model, &rng, &exemplars, &drafts);

        let candidates = candidates_for(&ctx, Facet::Voice);
        assert!(
            candidates.len() >= 2,
            "the cloze should still be a candidate behind the probe"
        );
        assert!(matches!(candidates[0].kind, QuestKind::VoiceProbe { .. }));
        assert!(
            candidates
                .iter()
                .any(|d| matches!(d.kind, QuestKind::Cloze { .. })),
            "the mechanical candidate was dropped rather than ranked behind"
        );
    }

    #[test]
    fn a_model_draft_reaches_a_real_quest_set() {
        // The end-to-end version: with a budget wide enough to cover every
        // facet, the written probe is among what is issued.
        let model = persona();
        let rng = SeededRng::new(3);
        let drafts = vec![probe(QuestKind::VoiceProbe {
            prompt: "how would you describe your morning?".to_owned(),
            ghost_answer: "flatly, and shorter than expected".to_owned(),
        })];
        let ctx = context_full(&model, &rng, &[], &drafts);
        let quests = DeterministicGenerator.generate(&ctx, 10).expect("generate");

        assert!(
            quests
                .iter()
                .any(|q| matches!(q.kind, QuestKind::VoiceProbe { .. })),
            "the written probe never made it into the day's set"
        );
    }

    #[test]
    fn no_drafts_is_exactly_todays_behaviour() {
        // The default build. Adding the seam must not change what a vault with
        // no model produces.
        let model = persona();
        let exemplars = vec![(
            MemoryId::new(1, [1u8; 10]),
            "I walked to the river before work and left the phone at home.".to_owned(),
        )];

        let with_empty = DeterministicGenerator
            .generate(
                &context_full(&model, &SeededRng::new(7), &exemplars, &[]),
                5,
            )
            .expect("generate");
        let via_old_path = DeterministicGenerator
            .generate(&context_with(&model, &SeededRng::new(7), &exemplars), 5)
            .expect("generate");

        assert_eq!(with_empty.len(), via_old_path.len());
        for (a, b) in with_empty.iter().zip(via_old_path.iter()) {
            assert_eq!(a.kind.committed_answer(), b.kind.committed_answer());
        }
    }
}
