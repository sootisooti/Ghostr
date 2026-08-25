//! Stage 2–3: clustering, and structured extraction from each cluster.
//!
//! # This is where untrusted text meets the model
//!
//! Clusters contain corpus content, some of it written by other people. The
//! defences are structural (THREAT_MODEL §T7):
//!
//! - The extractor runs with **no tools and no network access**, so there is
//!   nothing for an injected instruction to actuate. This is the mitigation that
//!   matters; the rest is depth.
//! - Every call uses schema-validated structured output. Prose that will not
//!   parse is discarded, not interpreted.
//! - Content enters as [`Role::CorpusData`](ghostr_llm::model::Role::CorpusData),
//!   never as instruction.
//!
//! Residual risk, stated plainly: a schema constrains the *shape* of a response,
//! not its *content*. A clever injection can still bias a summary inside a valid
//! schema. The defence is traceability — evidence links make a poisoned claim
//! findable and shreddable — not prevention.

use ghostr_core::ids::{EntityId, MemoryId, ThreadId};
use ghostr_core::memory::Memory;
use ghostr_llm::schema::{Schema, StructuredOutput};
use serde::{Deserialize, Serialize};

/// Groups memories that belong to the same beat of a day.
///
/// Must be deterministic given the same inputs and a seeded RNG: two runs over
/// one day producing different clusters would produce different footage, and
/// therefore a different commitment for the same data.
pub trait Clusterer: Send + Sync {
    /// Groups a window's memories.
    fn cluster(&self, memories: &[Memory]) -> Vec<Cluster>;
}

/// A group of related memories.
#[derive(Debug, Clone, PartialEq)]
pub struct Cluster {
    /// The memories, in time order.
    pub memory_ids: Vec<MemoryId>,
    /// Entities appearing across the cluster.
    pub entities: Vec<EntityId>,
    /// An existing thread this continues, if any.
    pub continues_thread: Option<ThreadId>,
    /// How tightly grouped, in `0.0..=1.0`.
    pub cohesion: f32,
}

/// What the model returns for one cluster.
///
/// Every field is constrained. Note what is absent: no free-form "notes" field,
/// no place for the model to say something the schema did not ask for. Each
/// open string is a place an injected instruction can survive validation, so
/// there are as few as the task allows.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ClusterExtraction {
    /// One-line summary.
    pub summary: String,
    /// Entities the model believes are referenced.
    pub entity_mentions: Vec<EntityMention>,
    /// This cluster's contribution to the day's mood.
    pub mood_contribution: MoodContribution,
    /// Whether this opens, advances, or closes a thread.
    pub thread_signal: ThreadSignal,
    /// How salient, in `0.0..=1.0`.
    pub salience: f32,
    /// Anything the model could not determine.
    pub unresolved: Vec<String>,
}

impl StructuredOutput for ClusterExtraction {
    fn schema() -> Schema {
        todo!("return the hand-written JSON Schema for a cluster extraction")
    }
}

/// A believed entity reference.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EntityMention {
    /// The surface form as it appeared.
    pub surface: String,
    /// How the model read it.
    pub role: String,
    /// Confidence, in `0.0..=1.0`.
    pub confidence: f32,
}

/// A cluster's contribution to the day's mood.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MoodContribution {
    /// Pleasantness, in `-1.0..=1.0`.
    pub valence: f32,
    /// Activation, in `0.0..=1.0`.
    pub arousal: f32,
    /// Whether the user said this or the model inferred it.
    ///
    /// Stated always outweighs inferred at compose time. The user is the
    /// authority on how their day felt.
    pub stated: bool,
    /// Confidence, in `0.0..=1.0`.
    pub confidence: f32,
}

/// What a cluster does to a thread.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ThreadSignal {
    /// Starts something new.
    Opens,
    /// Continues something.
    Advances,
    /// Finishes something.
    Closes,
    /// Bears on no thread.
    None,
}
