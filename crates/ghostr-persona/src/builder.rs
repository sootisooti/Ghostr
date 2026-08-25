//! Distillation and diffing.

use ghostr_core::footage::Footage;
use ghostr_core::ids::PersonaVersion;
use ghostr_core::memory::Memory;
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
    /// The first-party memories those days refer to.
    ///
    /// First-party only, filtered by the caller: voice exemplars are drawn from
    /// this slice, and a feed item becoming an exemplar is how a stranger's
    /// voice ends up in the ghost's mouth (THREAT_MODEL §T7).
    pub first_party: &'a [&'a Memory],
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

/// The deterministic builder.
///
/// Computes what is countable and carries forward what is not. See
/// [`crate::distill`] for which facets fall on which side of that line, and why
/// an empty facet is the honest output rather than a guessed one.
#[derive(Debug, Default, Clone, Copy)]
pub struct DeterministicBuilder;

impl PersonaBuilder for DeterministicBuilder {
    fn distill(
        &self,
        prior: Option<&PersonaModel>,
        input: DistillInput<'_>,
    ) -> crate::Result<PersonaModel> {
        let corpus = crate::distill::Corpus {
            footage: input.footage,
            first_party: input.first_party,
        };
        crate::distill::distill(prior, &corpus, input.deltas, input.now, input.next_ordinal)
    }

    fn diff(&self, from: &PersonaModel, to: &PersonaModel) -> PersonaDiff {
        crate::diff::diff(from, to)
    }

    fn should_distill(&self, since: Timestamp, pending: &[PersonaDelta]) -> bool {
        // The trait does not carry a clock, so the weekly arm cannot be
        // evaluated here; the engine calls `distill::should_distill` directly
        // with `now`. This answers the half that is decidable from the
        // arguments given, which is the delta threshold.
        crate::distill::should_distill(since, since, pending, false)
    }
}

/// Proposes a version without adopting it.
///
/// Distillation and adoption are separate steps so a user can read the diff
/// before the ghost starts speaking from a new model. Large changes should not
/// take effect silently.
///
/// # Errors
///
/// Propagates whatever [`PersonaBuilder::distill`] returns.
pub fn propose(
    builder: &dyn PersonaBuilder,
    head: Option<&PersonaModel>,
    input: DistillInput<'_>,
) -> crate::Result<CandidateVersion> {
    let mut model = builder.distill(head, input)?;
    let diff = match head {
        Some(current) => builder.diff(current, &model),
        // Nothing to diff against: the first version is entirely new, and
        // saying so beats an empty change list that reads like "nothing
        // happened".
        None => PersonaDiff {
            from: PersonaVersion::genesis(),
            to: model.version,
            changes: Vec::new(),
        },
    };
    model.diff = Some(diff.clone());

    Ok(CandidateVersion {
        warrants_review: head.is_some() && crate::diff::warrants_review(&diff),
        replaces: head.map(|h| h.version),
        model,
        diff,
    })
}
