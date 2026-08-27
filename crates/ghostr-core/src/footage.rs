//! [`Footage`] — one sealing window's compiled memory, and its commitment.
//!
//! Footage is the ghost's long-term memory substrate, not a summary for the user
//! to read; the human-readable recap is a rendering of it. Once
//! [`Footage::sealed_at`] is set the record is immutable (SPEC I2) and its
//! [`Commitment`] is part of a chain that is never rewritten (SPEC I3).

use chrono::NaiveDate;
use chrono_tz::Tz;
use serde::{Deserialize, Serialize};

use crate::hash::Hash32;
use crate::ids::{EntityId, MemoryId, PersonaVersion, ThreadId};
use crate::time::Timestamp;

/// One sealing window, compiled and committed.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Footage {
    /// Chain index. Monotonic, gapless, starting at 1 (SPEC I3).
    pub seq: u64,
    /// Local calendar date of the cutoff.
    pub date: NaiveDate,
    /// The IANA zone actually in effect, which may differ from the home zone.
    pub tz: Tz,
    /// Half-open `[start, cutoff)` on absolute UTC instants.
    ///
    /// Absolute rather than local, so a timezone change mid-window cannot
    /// double-count or drop a memory (SPEC Q11).
    pub window: (Timestamp, Timestamp),
    /// Whether the window contained no memories.
    ///
    /// Empty days still seal and still advance `seq`: a gap in the chain is
    /// indistinguishable from a deletion, so there are no gaps.
    pub empty: bool,

    /// What mattered, ranked by salience.
    pub highlights: Vec<Highlight>,
    /// Who appeared, and how.
    pub people: Vec<PersonBeat>,
    /// The day's affective reading.
    pub mood: MoodReading,
    /// Threads opened or still running.
    pub open_threads: Vec<Thread>,
    /// Threads that closed today, having opened earlier.
    pub closed_loops: Vec<ThreadId>,
    /// Questions the extractor could not answer.
    pub unresolved: Vec<OpenQuestion>,

    /// Every memory in the window, sorted.
    pub memory_ids: Vec<MemoryId>,
    /// Corrections to *earlier sealed* footage. Never edits to this one.
    pub amendments: Vec<Amendment>,
    /// The persona version in effect when this was sealed.
    pub persona_version: PersonaVersion,

    /// The chain commitment.
    pub commitment: Commitment,
    /// When this footage became immutable.
    pub sealed_at: Timestamp,
}

/// Something that mattered.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Highlight {
    /// One-line summary.
    pub summary: String,
    /// The memories this is drawn from.
    ///
    /// Never empty. A highlight with no evidence is a hallucination and is
    /// dropped in validation (SPEC §6).
    pub memory_ids: Vec<MemoryId>,
    /// Rank weight, in `0.0..=1.0`.
    pub salience: f32,
}

/// A person's appearance in the day.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PersonBeat {
    /// Who.
    pub entity: EntityId,
    /// How they appeared.
    pub interaction: InteractionKind,
    /// How the interaction felt, in `-1.0..=1.0`, if inferable.
    pub valence: Option<f32>,
    /// Supporting memories.
    pub memory_ids: Vec<MemoryId>,
}

/// How a person appeared in a day.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum InteractionKind {
    /// Met in person.
    Met,
    /// Exchanged messages.
    Messaged,
    /// Mentioned the user publicly.
    MentionedBy,
    /// The user mentioned them.
    Mentioned,
    /// The user thought about them without contact.
    ThoughtAbout,
}

/// The day's affective reading.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MoodReading {
    /// Pleasantness, in `-1.0..=1.0`.
    pub valence: f32,
    /// Activation, in `0.0..=1.0`.
    pub arousal: f32,
    /// Free-text labels.
    pub labels: Vec<String>,
    /// Confidence in the reading, in `0.0..=1.0`.
    pub confidence: f32,
    /// Whether the user said this or the ghost inferred it.
    ///
    /// Stated mood always outweighs inferred mood when the two disagree. The
    /// user is the authority on how their day felt.
    pub basis: MoodBasis,
}

/// Where a [`MoodReading`] came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MoodBasis {
    /// The user said so.
    Stated,
    /// Inferred from content.
    Inferred,
    /// Both, with stated taking precedence.
    Mixed,
}

/// An open loop, tracked across days.
///
/// The piece that makes footage a memory substrate rather than a diary. A stable
/// [`ThreadId`] means "the tz bug", opened on day 40 and closed on day 47, is one
/// object with a lifespan — so the ghost can answer "what am I still sitting on?"
/// without re-reading a week of prose.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Thread {
    /// Stable across days.
    pub id: ThreadId,
    /// Short human-readable title.
    pub title: String,
    /// The `seq` this thread first appeared in.
    pub opened_seq: u64,
    /// The most recent `seq` that touched it.
    pub last_touched_seq: u64,
    /// Where it stands.
    pub state: ThreadState,
    /// Supporting memories across its whole life.
    pub memory_ids: Vec<MemoryId>,
}

/// Where a [`Thread`] stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ThreadState {
    /// Active.
    Open,
    /// Untouched long enough to look stalled.
    Stalled,
    /// Resolved.
    Closed,
    /// Dropped without resolution — distinct from closed, and worth knowing.
    Abandoned,
}

/// Something the extractor could not determine.
///
/// Recorded rather than guessed. An honest "I could not tell who this was about"
/// is better memory than a confident wrong entity.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OpenQuestion {
    /// What is unclear.
    pub question: String,
    /// The memories that raised it.
    pub memory_ids: Vec<MemoryId>,
}

/// A correction to an already-sealed footage.
///
/// The only mechanism by which the past changes. The earlier record keeps its
/// commitment; the amendment sits in the current day and points backwards
/// (SPEC I2, Q16).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Amendment {
    /// Which sealed footage this corrects.
    pub target_seq: u64,
    /// Why.
    pub reason: AmendmentReason,
    /// What the correction says.
    pub note: String,
    /// Supporting memories, which live in the *current* window.
    pub memory_ids: Vec<MemoryId>,
}

/// Why an [`Amendment`] exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum AmendmentReason {
    /// The user corrected something the ghost got wrong.
    Correction,
    /// A memory arrived after its window had sealed.
    LateArrival,
    /// Content was crypto-shredded (SPEC Q6).
    Redaction,
}

/// One day's position in the commitment chain (SPEC §7.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Commitment {
    /// Merkle root over this window's leaves.
    pub merkle_root: Hash32,
    /// The previous day's link. Genesis for `seq == 1`.
    pub prev_link: Hash32,
    /// `H_tag(Link, prev_link || merkle_root || seq || date || tz)`.
    pub link: Hash32,
    /// How many leaves went into the root, which pins proof shape.
    pub leaf_count: u32,
    /// Which leaf set this day's root was built over.
    ///
    /// The one field that makes changing the commitment scheme survivable. A
    /// day is verified under the rules it was *sealed* under, not the rules the
    /// current build prefers — so adding a leaf kind does not invalidate every
    /// chain that predates it, which would be unrecoverable for users because
    /// the old roots are already in Bitcoin (CLAUDE.md §4.7).
    ///
    /// Deliberately **outside every preimage**: the link commits to
    /// `prev_link || merkle_root || seq || date || tz` and nothing else, so
    /// recording a version here moves no existing hash.
    #[serde(default = "CommitmentVersion::original")]
    pub version: CommitmentVersion,
}

/// Which leaves a day's Merkle root was built over.
///
/// Ordered oldest first. A new variant is added when the leaf set changes, and
/// the old variants stay forever — a chain sealed under one of them still has
/// to verify.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum CommitmentVersion {
    /// Metadata and memories.
    ///
    /// Everything sealed before quests reached the tree. Assumed for any stored
    /// footage that carries no version at all, which is exactly the days sealed
    /// by a build that had never heard of this field.
    MemoriesOnly,
    /// Metadata, memories, the quests issued that day, and the verdicts given
    /// that day (SPEC §7.3).
    WithQuests,
}

impl CommitmentVersion {
    /// What a footage with no recorded version was sealed under.
    #[must_use]
    pub const fn original() -> Self {
        Self::MemoriesOnly
    }

    /// What this build seals new days under.
    #[must_use]
    pub const fn current() -> Self {
        Self::WithQuests
    }
}

/// The head of the chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainTip {
    /// The most recent sealed `seq`.
    pub seq: u64,
    /// Its link.
    pub link: Hash32,
    /// When it was sealed.
    pub sealed_at: Timestamp,
}
