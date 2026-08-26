//! [`PersonaModel`] — the ghost itself.
//!
//! The model is **symbolic, not weights**, and three properties follow from that
//! choice (SPEC §3.6):
//!
//! - *Auditable.* Every claim carries `evidence`, so "why do you think I believe
//!   that?" has a straight answer — and a poisoned belief is traceable to the
//!   exact note that introduced it (THREAT_MODEL §T7).
//! - *Diffable.* [`PersonaDiff`] is a real type. "The ghost changed its mind
//!   about you" is a reviewable event rather than a silent weight update.
//! - *Deletable.* Shredding a memory can actually remove its influence. You
//!   cannot un-train a fine-tune.

use serde::{Deserialize, Serialize};

use crate::ids::{EntityId, MemoryId, PersonaVersion};
use crate::quest::Facet;
use crate::time::Timestamp;

/// One version of the ghost.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PersonaModel {
    /// Ordinal plus content hash.
    pub version: PersonaVersion,
    /// The version this was distilled from.
    pub parent: Option<PersonaVersion>,
    /// When it was distilled.
    pub created_at: Timestamp,
    /// The model's content.
    pub facets: Facets,
    /// Which memories fed this distillation.
    pub derived_from: Vec<MemoryId>,
    /// What changed against the parent, and why.
    pub diff: Option<PersonaDiff>,
}

/// The six facets that make up a persona.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Facets {
    /// How the user writes.
    pub voice: VoiceProfile,
    /// What they think.
    pub opinions: Vec<Stance>,
    /// Who they know.
    pub relationships: Vec<Relation>,
    /// What they do, and when.
    pub routines: Vec<Routine>,
    /// What they would never say or do.
    pub boundaries: Vec<Boundary>,
    /// Durable biographical facts.
    pub lore: Vec<LoreFact>,
}

/// How the user writes and speaks.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VoiceProfile {
    /// Formality, warmth, hedging, profanity.
    pub register: Register,
    /// Characteristic words and phrases, with rates.
    pub lexicon: Vec<LexicalTic>,
    /// Sentence length distribution and clause depth.
    pub syntax: SyntaxStats,
    /// Em-dash usage, capitalisation habits, emoji rate.
    pub punctuation: PunctuationHabits,
    /// Verbatim utterances used as few-shot exemplars.
    ///
    /// [`TrustLevel::FirstParty`](crate::sensitivity::TrustLevel::FirstParty)
    /// only. Letting third-party text become an exemplar is how a stranger's
    /// voice ends up in the ghost's mouth (THREAT_MODEL §T7).
    pub exemplars: Vec<MemoryId>,
}

/// Where the user sits on four continuous axes, each in `0.0..=1.0`.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Register {
    /// Formal versus casual.
    pub formality: f32,
    /// Warm versus cool.
    pub warmth: f32,
    /// How much the user qualifies claims.
    pub hedging: f32,
    /// How much they swear.
    pub profanity: f32,
}

/// A characteristic word or phrase.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LexicalTic {
    /// The word or phrase.
    pub phrase: String,
    /// Occurrences per thousand words.
    pub rate_per_kiloword: f32,
    /// How distinctive this is against a general baseline.
    pub distinctiveness: f32,
}

/// Sentence-level statistics.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct SyntaxStats {
    /// Mean sentence length in words.
    pub mean_sentence_words: f32,
    /// Standard deviation of sentence length.
    pub sentence_words_stddev: f32,
    /// Mean subordinate clause depth.
    pub mean_clause_depth: f32,
    /// Fraction of sentences that are fragments.
    pub fragment_rate: f32,
}

/// Punctuation and typography habits.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct PunctuationHabits {
    /// Em-dashes per thousand words.
    pub em_dash_rate: f32,
    /// Fraction of sentences beginning lowercase.
    pub lowercase_start_rate: f32,
    /// Emoji per thousand words.
    pub emoji_rate: f32,
    /// Ellipses per thousand words.
    pub ellipsis_rate: f32,
    /// Fraction of sentences ending without terminal punctuation.
    pub unterminated_rate: f32,
}

/// A position the user holds.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Stance {
    /// What it is about.
    pub topic: String,
    /// What they think.
    pub position: String,
    /// How strongly, in `0.0..=1.0`.
    pub strength: f32,
    /// How stable this has been over time, in `0.0..=1.0`.
    pub stability: f32,
    /// Supporting memories.
    pub evidence: Vec<MemoryId>,
    /// When this was last observed.
    pub last_seen: Timestamp,
    /// Memories that contradict this stance.
    ///
    /// Held explicitly rather than resolved away. People are inconsistent, and a
    /// model that smooths that out is modelling a simpler person than the one it
    /// is cloning.
    pub contradicted_by: Vec<MemoryId>,
}

/// A tie to another person.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Relation {
    /// Who. The real name lives in the encrypted entity table.
    pub entity: EntityId,
    /// Their role: colleague, sibling, ex.
    pub role: String,
    /// How close, in `0.0..=1.0`.
    pub closeness: f32,
    /// Typical days between contact.
    pub cadence_days: Option<f32>,
    /// What they talk about.
    pub topics: Vec<String>,
    /// Supporting memories.
    pub evidence: Vec<MemoryId>,
}

/// A recurring pattern.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Routine {
    /// What happens.
    pub pattern: String,
    /// When, as a human-readable schedule ("weekday mornings").
    pub schedule: String,
    /// How reliable the pattern is, in `0.0..=1.0`.
    pub confidence: f32,
    /// Supporting memories.
    pub evidence: Vec<MemoryId>,
}

/// Something the user would not say or do.
///
/// The negative space, and the part that keeps a "ghost speaks" mode from
/// embarrassing its principal. A model that only knows what someone *would* say
/// has no way to decline.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Boundary {
    /// What the user avoids.
    pub description: String,
    /// How firm, in `0.0..=1.0`.
    pub firmness: f32,
    /// Supporting memories.
    pub evidence: Vec<MemoryId>,
}

/// A durable biographical fact.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LoreFact {
    /// The fact.
    pub statement: String,
    /// Confidence, in `0.0..=1.0`.
    pub confidence: f32,
    /// Supporting memories.
    pub evidence: Vec<MemoryId>,
}

/// What changed between two persona versions.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PersonaDiff {
    /// The version this diff is from.
    pub from: PersonaVersion,
    /// The version this diff is to.
    pub to: PersonaVersion,
    /// The individual changes.
    pub changes: Vec<FacetChange>,
}

/// One change within a [`PersonaDiff`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FacetChange {
    /// Which facet moved.
    pub facet: Facet,
    /// What kind of movement.
    pub kind: ChangeKind,
    /// Human-readable description, suitable for review by a non-developer.
    pub description: String,
    /// What caused it.
    pub caused_by: Vec<MemoryId>,
}

/// What kind of movement a [`FacetChange`] represents.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ChangeKind {
    /// Something new appeared.
    Added,
    /// Something disappeared.
    Removed,
    /// A value moved without changing meaning, e.g. a strength adjustment.
    Adjusted,
    /// A position reversed.
    Reversed,
    /// A contradiction was recorded without resolving the stance.
    Contradicted,
}

/// A pending adjustment, queued by a correction and not yet applied.
///
/// Deltas accumulate and are applied at the next distillation rather than
/// immediately, so a version bump reflects a batch of evidence rather than one
/// bad morning. A single correction never overturns a stance backed by fifty
/// memories; it lowers `strength` and adds to `contradicted_by` until the weight
/// genuinely shifts (SPEC §4.5).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PersonaDelta {
    /// Which facet this bears on.
    pub facet: Facet,
    /// The evidence the corrected claim rested on.
    ///
    /// This locates the claim: a delta is applied to the facet entries whose
    /// own `evidence` names this memory. It is deliberately *not* the
    /// correction — a rejection with no explanation corrects nothing yet still
    /// carries signal, and a delta that could only exist alongside written
    /// words would silently drop those.
    pub memory_id: MemoryId,
    /// The memory carrying the user's own words, when they wrote any.
    ///
    /// `None` for a bare rejection. Recorded in `contradicted_by` when present,
    /// which is what keeps a weakened stance traceable to the sentence that
    /// weakened it.
    pub correction_id: Option<MemoryId>,
    /// How much weight to give it, in `0.0..=1.0`.
    pub weight: f32,
    /// When it was queued.
    pub queued_at: Timestamp,
    /// Whether it came from a held-out quest.
    ///
    /// Must be `false` for anything that reaches distillation. Carried here so
    /// the invariant is checkable at the point of application rather than
    /// assumed upstream (SPEC I7).
    pub from_holdout: bool,
}
