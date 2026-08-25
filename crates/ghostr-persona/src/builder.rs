//! Distillation and diffing.

use ghostr_core::footage::Footage;
use ghostr_core::ids::PersonaVersion;
use ghostr_core::persona::{PersonaDelta, PersonaDiff, PersonaModel};
use ghostr_core::time::Timestamp;

/// Builds persona versions from footage and queued corrections.
pub trait PersonaBuilder: Send + Sync {
    /// Distils a new version.
    ///
    /// Implementations must reject any [`PersonaDelta`] with `from_holdout` set,
    /// returning [`Error::HoldoutLeak`](crate::Error::HoldoutLeak) rather than
    /// filtering it out. A silent filter would hide the upstream bug that
    /// produced it, and that bug invalidates every score computed since.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InsufficientCorpus`](crate::Error::InsufficientCorpus),
    /// [`Error::HoldoutLeak`](crate::Error::HoldoutLeak), or
    /// [`Error::UnsupportedClaim`](crate::Error::UnsupportedClaim).
    fn distill(
        &self,
        prior: Option<&PersonaModel>,
        input: DistillInput<'_>,
    ) -> crate::Result<PersonaModel>;

    /// Computes the diff between two versions.
    ///
    /// Pure and total. The output is read by humans before a version is
    /// accepted, which is the review step that catches a poisoned stance before
    /// it starts answering quests (THREAT_MODEL §T7).
    fn diff(&self, from: &PersonaModel, to: &PersonaModel) -> PersonaDiff;

    /// Whether enough new evidence has accumulated to justify a distillation.
    ///
    /// Distillation is expensive on a local model and a version bump invalidates
    /// nothing but adds noise, so the default cadence is weekly or on a delta
    /// threshold rather than continuous.
    fn should_distill(&self, since: Timestamp, pending: &[PersonaDelta]) -> bool;
}

/// What a distillation reads.
#[derive(Debug, Clone, Copy)]
pub struct DistillInput<'a> {
    /// Recent sealed footage, oldest first.
    pub footage: &'a [Footage],
    /// Queued corrections. Must all be non-holdout.
    pub deltas: &'a [PersonaDelta],
    /// When this distillation runs.
    pub now: Timestamp,
    /// Ordinal for the new version.
    pub next_ordinal: u32,
}

/// A candidate version awaiting review before it becomes head.
///
/// Distillation and adoption are separate steps so a user can read the diff
/// before the ghost starts speaking from a new model. Large changes should not
/// take effect silently.
#[derive(Debug, Clone, PartialEq)]
pub struct CandidateVersion {
    /// The proposed model.
    pub model: PersonaModel,
    /// What changes against the current head.
    pub diff: PersonaDiff,
    /// Whether the diff is large enough to warrant explicit review.
    pub warrants_review: bool,
    /// The version this replaces.
    pub replaces: Option<PersonaVersion>,
}
