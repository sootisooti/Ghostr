//! Distillation and diffing.

use ghostr_core::footage::Footage;
use ghostr_core::ids::PersonaVersion;
use ghostr_core::memory::Memory;
use ghostr_core::persona::{ChangeKind, FacetChange, PersonaDelta, PersonaDiff, PersonaModel};
use ghostr_core::quest::Facet;
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
    /// The memories eligible to be voice exemplars.
    ///
    /// [`TrustLevel::may_be_exemplar`] decides membership and the caller
    /// filters: a feed item becoming an exemplar is how a stranger's voice ends
    /// up in the ghost's mouth (THREAT_MODEL §T7).
    ///
    /// [`TrustLevel::may_be_exemplar`]: ghostr_core::sensitivity::TrustLevel::may_be_exemplar
    pub first_party: &'a [&'a Memory],
    /// The memories a claim may rest on.
    ///
    /// A superset of `first_party`: [`TrustLevel::may_source_stance`] also
    /// admits `SelfReported`, because a health or people log is the user
    /// asserting something about themselves. It is not their prose, so it may
    /// never be a voice exemplar — which is exactly why these are two slices
    /// and not one.
    ///
    /// [`TrustLevel::may_source_stance`]: ghostr_core::sensitivity::TrustLevel::may_source_stance
    pub claimable: &'a [&'a Memory],
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
            claimable: input.claimable,
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
        // The first version is entirely new, so it is described rather than
        // compared. This arm used to build an empty change list under a comment
        // saying an empty change list "reads like nothing happened" — and the
        // renderer duly printed `v0 → v1: nothing changed` for the single most
        // consequential adoption in a vault's life. The on-ramp says "read the
        // diff and adopt"; there was nothing to read.
        None => PersonaDiff {
            from: PersonaVersion::genesis(),
            to: model.version,
            changes: first_version_changes(&model),
        },
    };
    model.diff = Some(diff.clone());

    Ok(CandidateVersion {
        // A first version always warrants reading. It was `head.is_some() &&`,
        // which made the one adoption that establishes every facet from scratch
        // the only one that could never ask to be read.
        warrants_review: head.is_none_or(|_| crate::diff::warrants_review(&diff)),
        replaces: head.map(|h| h.version),
        model,
        diff,
    })
}

/// What a first persona version established, as changes a reader can read.
///
/// Not a diff — there is nothing to diff against — but the same shape, because
/// the alternative is a blank review step exactly where the most was decided.
/// Counts and measured values only: naming the memories behind a voice register
/// would be inventing evidence, since voice is measured over the whole corpus
/// rather than traced to particular notes.
fn first_version_changes(model: &PersonaModel) -> Vec<FacetChange> {
    let mut changes = Vec::new();
    let voice = &model.facets.voice;

    changes.push(FacetChange {
        facet: Facet::Voice,
        kind: ChangeKind::Added,
        description: format!(
            "voice established from {} exemplar(s) \
             (formality {:.2}, warmth {:.2}, hedging {:.2}, profanity {:.2})",
            voice.exemplars.len(),
            voice.register.formality,
            voice.register.warmth,
            voice.register.hedging,
            voice.register.profanity,
        ),
        caused_by: Vec::new(),
    });

    // `Facets` has six fields and `Facet` has five variants: boundaries — "what
    // they would never say or do" — have no facet to be reported under, so
    // neither this nor `diff` can name a change to them. Left visible rather
    // than silently skipped, since a boundary appearing or vanishing is exactly
    // the kind of movement a reader would want flagged.
    for (facet, count, noun) in [
        (Facet::Opinion, model.facets.opinions.len(), "opinion"),
        (
            Facet::Relationship,
            model.facets.relationships.len(),
            "relationship",
        ),
        (Facet::Routine, model.facets.routines.len(), "routine"),
        (Facet::Lore, model.facets.lore.len(), "biographical fact"),
    ] {
        // A facet with nothing in it is not a change. Listing "0 opinions"
        // would pad the review with lines that carry no decision.
        if count == 0 {
            continue;
        }
        changes.push(FacetChange {
            facet,
            kind: ChangeKind::Added,
            description: format!(
                "{count} {noun}{} recorded",
                if count == 1 { "" } else { "s" }
            ),
            caused_by: Vec::new(),
        });
    }

    changes
}

#[cfg(test)]
mod first_version_tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use ghostr_core::time::Timestamp;

    use crate::distill::fixtures::corpus_memories;

    use super::*;

    /// A first proposal, through `propose` itself.
    ///
    /// Written this way after the first attempt asserted on
    /// `first_version_changes` directly and passed both mutations — restoring
    /// the empty change list and restoring `head.is_some() &&` left it green,
    /// because it proved the helper formats and never that `propose` calls it.
    /// The path under test is the one the CLI runs.
    fn first_proposal() -> CandidateVersion {
        let memories = corpus_memories(30);
        let refs: Vec<&ghostr_core::memory::Memory> = memories.iter().collect();
        propose(
            &crate::DeterministicBuilder,
            None,
            DistillInput {
                footage: &[],
                first_party: &refs,
                claimable: &refs,
                deltas: &[],
                now: Timestamp::new(0, 0),
                next_ordinal: 1,
            },
        )
        .expect("propose a first version")
    }

    /// The first persona says what it established.
    ///
    /// It used to say `v0 → v1: nothing changed`, under a comment in `propose`
    /// noting that an empty change list "reads like nothing happened". The
    /// on-ramp tells a user to read the diff before adopting, and for the one
    /// adoption that establishes every facet from scratch there was nothing to
    /// read.
    #[test]
    fn a_first_version_describes_itself_rather_than_claiming_nothing_changed() {
        let candidate = first_proposal();
        assert!(
            !candidate.diff.changes.is_empty(),
            "the first version reported no changes at all"
        );
        let voice = candidate
            .diff
            .changes
            .iter()
            .find(|c| c.facet == Facet::Voice)
            .expect("a first version always establishes a voice");
        assert_eq!(voice.kind, ChangeKind::Added);
        assert!(
            voice.description.contains("formality"),
            "the voice line does not say what was measured: {}",
            voice.description
        );
    }

    /// And it asks to be read.
    ///
    /// `warrants_review` was `head.is_some() && …`, so the largest change a
    /// vault ever sees was the only one that could never request a look.
    #[test]
    fn a_first_version_warrants_review() {
        assert!(
            first_proposal().warrants_review,
            "the first persona did not ask to be read"
        );
    }

    /// An empty facet is not reported as a change.
    ///
    /// Without this the review is padded with "0 opinions recorded" lines that
    /// carry no decision, which is its own way of making the step unreadable.
    #[test]
    fn a_facet_with_nothing_in_it_is_not_a_change() {
        let candidate = first_proposal();
        assert!(
            candidate
                .diff
                .changes
                .iter()
                .all(|c| !c.description.starts_with('0')),
            "an empty facet was reported: {:?}",
            candidate.diff.changes
        );
    }

    /// A second version still diffs against its parent.
    ///
    /// The first-version arm must not swallow the normal path: a vault with a
    /// head compares, and an unchanged corpus genuinely has nothing to say.
    #[test]
    fn a_later_version_still_compares_against_its_parent() {
        let first = first_proposal().model;
        let memories = corpus_memories(30);
        let refs: Vec<&ghostr_core::memory::Memory> = memories.iter().collect();
        let second = propose(
            &crate::DeterministicBuilder,
            Some(&first),
            DistillInput {
                footage: &[],
                first_party: &refs,
                claimable: &refs,
                deltas: &[],
                now: Timestamp::new(0, 0),
                next_ordinal: 2,
            },
        )
        .expect("propose a second version");

        assert_eq!(second.replaces, Some(first.version));
        assert!(
            second.diff.changes.is_empty(),
            "the same corpus produced changes against itself: {:?}",
            second.diff.changes
        );
    }
}
