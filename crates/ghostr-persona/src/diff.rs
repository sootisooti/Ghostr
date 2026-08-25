//! Diffing two persona versions.
//!
//! This is the review step. "The ghost changed its mind about you" should be a
//! reviewable event rather than a silent weight update, and a diff nobody can
//! read is not a review — so every [`FacetChange::description`] is written for a
//! person, not a developer (SPEC §3.6).
//!
//! It is also where a poisoned belief surfaces. An injected note that plants a
//! stance produces a `ChangeKind::Added` on the opinion facet, with
//! `caused_by` naming the exact memory that introduced it (THREAT_MODEL §T7).

use ghostr_core::persona::{ChangeKind, FacetChange, PersonaDiff, PersonaModel};
use ghostr_core::quest::Facet;

/// How much a `0.0..=1.0` value must move before it is worth reporting.
///
/// Below this, a "change" is measurement noise from one extra note, and a diff
/// full of noise is a diff nobody reads — which costs more than the detail is
/// worth.
const NOTABLE: f32 = 0.05;

/// How many changes make a diff worth explicit review.
const REVIEW_THRESHOLD: usize = 5;

/// Computes the diff between two versions.
///
/// Pure and total.
#[must_use]
pub fn diff(from: &PersonaModel, to: &PersonaModel) -> PersonaDiff {
    let mut changes = Vec::new();
    voice_changes(from, to, &mut changes);
    opinion_changes(from, to, &mut changes);
    relationship_changes(from, to, &mut changes);
    routine_changes(from, to, &mut changes);

    PersonaDiff {
        from: from.version,
        to: to.version,
        changes,
    }
}

/// Whether a diff is large enough to warrant a human reading it before the
/// ghost starts speaking from the new model.
#[must_use]
pub fn warrants_review(diff: &PersonaDiff) -> bool {
    diff.changes.len() >= REVIEW_THRESHOLD
        // A reversal is always worth a look however small the diff: the ghost
        // now asserts the opposite of what it asserted yesterday, and its owner
        // should know before it says so out loud.
        || diff
            .changes
            .iter()
            .any(|c| c.kind == ChangeKind::Reversed)
}

/// Register and habit movements.
fn voice_changes(from: &PersonaModel, to: &PersonaModel, out: &mut Vec<FacetChange>) {
    let a = &from.facets.voice;
    let b = &to.facets.voice;

    for (name, before, after, rising, falling) in [
        (
            "formality",
            a.register.formality,
            b.register.formality,
            "writing more formally",
            "writing more casually",
        ),
        (
            "warmth",
            a.register.warmth,
            b.register.warmth,
            "warmer in tone",
            "cooler in tone",
        ),
        (
            "hedging",
            a.register.hedging,
            b.register.hedging,
            "qualifying claims more",
            "stating things more plainly",
        ),
        (
            "profanity",
            a.register.profanity,
            b.register.profanity,
            "swearing more",
            "swearing less",
        ),
    ] {
        if (after - before).abs() < NOTABLE {
            continue;
        }
        out.push(FacetChange {
            facet: Facet::Voice,
            kind: ChangeKind::Adjusted,
            description: format!(
                "{} ({name} {:.2} → {:.2})",
                if after > before { rising } else { falling },
                before,
                after
            ),
            // Voice is measured over the whole corpus rather than traced to
            // particular notes, so there is no honest subset to name here. An
            // arbitrary sample would look like evidence and would not be.
            caused_by: Vec::new(),
        });
    }

    let before = a.syntax.mean_sentence_words;
    let after = b.syntax.mean_sentence_words;
    if (after - before).abs() >= 2.0 {
        out.push(FacetChange {
            facet: Facet::Voice,
            kind: ChangeKind::Adjusted,
            description: format!(
                "{} sentences ({before:.1} → {after:.1} words)",
                if after > before { "longer" } else { "shorter" }
            ),
            caused_by: Vec::new(),
        });
    }
}

/// Stances added, dropped, reversed, or contradicted.
fn opinion_changes(from: &PersonaModel, to: &PersonaModel, out: &mut Vec<FacetChange>) {
    use std::collections::BTreeMap;

    let before: BTreeMap<&str, _> = from
        .facets
        .opinions
        .iter()
        .map(|s| (s.topic.as_str(), s))
        .collect();
    let after: BTreeMap<&str, _> = to
        .facets
        .opinions
        .iter()
        .map(|s| (s.topic.as_str(), s))
        .collect();

    for (topic, stance) in &after {
        match before.get(topic) {
            None => out.push(FacetChange {
                facet: Facet::Opinion,
                kind: ChangeKind::Added,
                description: format!("now holds a view on {topic}: {}", stance.position),
                caused_by: stance.evidence.clone(),
            }),
            Some(old) if old.position != stance.position => out.push(FacetChange {
                facet: Facet::Opinion,
                kind: ChangeKind::Reversed,
                description: format!(
                    "changed position on {topic}: {} → {}",
                    old.position, stance.position
                ),
                caused_by: stance.evidence.clone(),
            }),
            Some(old) if stance.contradicted_by.len() > old.contradicted_by.len() => {
                out.push(FacetChange {
                    facet: Facet::Opinion,
                    kind: ChangeKind::Contradicted,
                    // Recorded without resolving: people are inconsistent, and a
                    // model that smooths that out is modelling a simpler person
                    // than the one it is cloning.
                    description: format!(
                        "{topic}: new evidence contradicts the recorded view, which stands",
                    ),
                    caused_by: stance.contradicted_by.clone(),
                });
            }
            Some(old) if (stance.strength - old.strength).abs() >= NOTABLE => {
                out.push(FacetChange {
                    facet: Facet::Opinion,
                    kind: ChangeKind::Adjusted,
                    description: format!(
                        "{} on {topic} ({:.2} → {:.2})",
                        if stance.strength > old.strength {
                            "firmer"
                        } else {
                            "less firm"
                        },
                        old.strength,
                        stance.strength
                    ),
                    caused_by: stance.evidence.clone(),
                });
            }
            Some(_) => {}
        }
    }

    for (topic, stance) in &before {
        if !after.contains_key(topic) {
            out.push(FacetChange {
                facet: Facet::Opinion,
                kind: ChangeKind::Removed,
                description: format!("no longer holds a view on {topic}"),
                caused_by: stance.evidence.clone(),
            });
        }
    }
}

/// People appearing, disappearing, or moving closer.
fn relationship_changes(from: &PersonaModel, to: &PersonaModel, out: &mut Vec<FacetChange>) {
    use std::collections::BTreeMap;

    let before: BTreeMap<_, _> = from
        .facets
        .relationships
        .iter()
        .map(|r| (r.entity, r))
        .collect();
    let after: BTreeMap<_, _> = to
        .facets
        .relationships
        .iter()
        .map(|r| (r.entity, r))
        .collect();

    for (entity, relation) in &after {
        match before.get(entity) {
            None => out.push(FacetChange {
                facet: Facet::Relationship,
                kind: ChangeKind::Added,
                // The pseudonym, never the name: a diff is read on screen and
                // may be quoted into a bug report (I8).
                description: format!("{} appears in the corpus", entity.display_short()),
                caused_by: relation.evidence.clone(),
            }),
            Some(old) if (relation.closeness - old.closeness).abs() >= NOTABLE => {
                out.push(FacetChange {
                    facet: Facet::Relationship,
                    kind: ChangeKind::Adjusted,
                    description: format!(
                        "{} appears {} often ({:.2} → {:.2})",
                        entity.display_short(),
                        if relation.closeness > old.closeness {
                            "more"
                        } else {
                            "less"
                        },
                        old.closeness,
                        relation.closeness
                    ),
                    caused_by: relation.evidence.clone(),
                });
            }
            Some(_) => {}
        }
    }

    for (entity, relation) in &before {
        if !after.contains_key(entity) {
            out.push(FacetChange {
                facet: Facet::Relationship,
                kind: ChangeKind::Removed,
                description: format!("{} no longer appears", entity.display_short()),
                caused_by: relation.evidence.clone(),
            });
        }
    }
}

/// Routines starting or stopping.
fn routine_changes(from: &PersonaModel, to: &PersonaModel, out: &mut Vec<FacetChange>) {
    use std::collections::BTreeSet;

    let before: BTreeSet<&str> = from
        .facets
        .routines
        .iter()
        .map(|r| r.pattern.as_str())
        .collect();

    for routine in &to.facets.routines {
        if !before.contains(routine.pattern.as_str()) {
            out.push(FacetChange {
                facet: Facet::Routine,
                kind: ChangeKind::Added,
                description: format!("a new pattern: {}", routine.pattern),
                caused_by: routine.evidence.clone(),
            });
        }
    }

    let after: BTreeSet<&str> = to
        .facets
        .routines
        .iter()
        .map(|r| r.pattern.as_str())
        .collect();
    for routine in &from.facets.routines {
        if !after.contains(routine.pattern.as_str()) {
            out.push(FacetChange {
                facet: Facet::Routine,
                kind: ChangeKind::Removed,
                description: format!("stopped: {}", routine.pattern),
                caused_by: routine.evidence.clone(),
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use ghostr_core::ids::MemoryId;
    use ghostr_core::persona::{Relation, Routine, Stance};
    use ghostr_core::time::Timestamp;

    use crate::distill::fixtures::{corpus_memories, entity};

    use super::*;

    fn model() -> PersonaModel {
        let memories = corpus_memories(30);
        let refs: Vec<&ghostr_core::memory::Memory> = memories.iter().collect();
        crate::distill::distill(
            None,
            &crate::distill::Corpus {
                footage: &[],
                first_party: &refs,
            },
            &[],
            Timestamp::new(0, 0),
            1,
        )
        .expect("distil")
    }

    fn stance(topic: &str, position: &str, strength: f32) -> Stance {
        Stance {
            topic: topic.to_owned(),
            position: position.to_owned(),
            strength,
            stability: 0.5,
            evidence: vec![MemoryId::new(1, [1u8; 10])],
            last_seen: Timestamp::new(0, 0),
            contradicted_by: Vec::new(),
        }
    }

    #[test]
    fn an_unchanged_model_diffs_to_nothing() {
        let m = model();
        assert!(diff(&m, &m).changes.is_empty());
    }

    #[test]
    fn a_new_stance_shows_as_added_with_its_evidence() {
        let before = model();
        let mut after = before.clone();
        after
            .facets
            .opinions
            .push(stance("remote work", "prefers it", 0.8));

        let d = diff(&before, &after);
        let change = d
            .changes
            .iter()
            .find(|c| c.facet == Facet::Opinion)
            .expect("an opinion change");
        assert_eq!(change.kind, ChangeKind::Added);
        assert!(change.description.contains("remote work"));
        assert!(change.description.contains("prefers it"));
        // The audit trail: which memory introduced this.
        assert!(!change.caused_by.is_empty());
    }

    /// THREAT_MODEL §T7. An injected note that plants a stance shows up here,
    /// naming the memory that introduced it — which is what makes a poisoned
    /// belief traceable rather than merely present.
    #[test]
    fn a_planted_stance_is_traceable_to_the_memory_that_introduced_it() {
        let planted = MemoryId::new(99, [99u8; 10]);
        let before = model();
        let mut after = before.clone();
        let mut poisoned = stance("privacy", "overrated", 1.0);
        poisoned.evidence = vec![planted];
        after.facets.opinions.push(poisoned);

        let d = diff(&before, &after);
        let change = d
            .changes
            .iter()
            .find(|c| c.kind == ChangeKind::Added && c.facet == Facet::Opinion)
            .expect("the planted stance");
        assert_eq!(change.caused_by, vec![planted]);
    }

    #[test]
    fn a_reversed_position_is_reported_as_a_reversal() {
        let mut before = model();
        before
            .facets
            .opinions
            .push(stance("remote work", "prefers it", 0.8));
        let mut after = before.clone();
        after.facets.opinions[0].position = "dislikes it".to_owned();

        let d = diff(&before, &after);
        let change = d
            .changes
            .iter()
            .find(|c| c.kind == ChangeKind::Reversed)
            .expect("a reversal");
        assert!(change.description.contains("prefers it"));
        assert!(change.description.contains("dislikes it"));
    }

    /// A reversal is always worth reading, however small the diff: the ghost
    /// now asserts the opposite of what it asserted yesterday.
    #[test]
    fn a_single_reversal_warrants_review_on_its_own() {
        let mut before = model();
        before
            .facets
            .opinions
            .push(stance("remote work", "prefers it", 0.8));
        let mut after = before.clone();
        after.facets.opinions[0].position = "dislikes it".to_owned();

        let d = diff(&before, &after);
        assert_eq!(d.changes.len(), 1);
        assert!(warrants_review(&d));
    }

    /// Contradictions are recorded, never resolved away: people are
    /// inconsistent, and a model that smooths that out is modelling a simpler
    /// person than the one it is cloning.
    #[test]
    fn a_contradiction_is_recorded_and_the_stance_stands() {
        let mut before = model();
        before
            .facets
            .opinions
            .push(stance("remote work", "prefers it", 0.8));
        let mut after = before.clone();
        after.facets.opinions[0]
            .contradicted_by
            .push(MemoryId::new(7, [7u8; 10]));

        let d = diff(&before, &after);
        let change = d
            .changes
            .iter()
            .find(|c| c.kind == ChangeKind::Contradicted)
            .expect("a contradiction");
        assert!(change.description.contains("stands"));
        // And the position itself did not move.
        assert_eq!(after.facets.opinions[0].position, "prefers it");
    }

    /// Noise from one extra note is not a change. A diff full of it is a diff
    /// nobody reads, which costs more than the detail is worth.
    #[test]
    fn a_movement_below_the_threshold_is_not_reported() {
        let mut before = model();
        before
            .facets
            .opinions
            .push(stance("remote work", "prefers it", 0.80));
        let mut after = before.clone();
        after.facets.opinions[0].strength = 0.82;
        assert!(diff(&before, &after).changes.is_empty());

        after.facets.opinions[0].strength = 0.95;
        assert!(!diff(&before, &after).changes.is_empty());
    }

    /// I8. A diff is read on screen and may be quoted into a bug report, so it
    /// names the pseudonym rather than the person.
    #[test]
    fn a_relationship_change_names_the_pseudonym_not_the_person() {
        let before = model();
        let mut after = before.clone();
        let who = entity(3);
        after.facets.relationships.push(Relation {
            entity: who,
            role: String::new(),
            closeness: 0.4,
            cadence_days: None,
            topics: Vec::new(),
            evidence: vec![MemoryId::new(1, [1u8; 10])],
        });

        let d = diff(&before, &after);
        let change = d
            .changes
            .iter()
            .find(|c| c.facet == Facet::Relationship)
            .expect("a relationship change");
        assert!(change.description.contains(&who.display_short()));
        assert!(change.description.starts_with("ent:"));
    }

    #[test]
    fn a_dropped_relationship_is_reported_as_removed() {
        let mut before = model();
        before.facets.relationships.push(Relation {
            entity: entity(4),
            role: String::new(),
            closeness: 0.4,
            cadence_days: None,
            topics: Vec::new(),
            evidence: vec![MemoryId::new(1, [1u8; 10])],
        });
        let mut after = before.clone();
        after.facets.relationships.clear();

        let d = diff(&before, &after);
        assert!(
            d.changes
                .iter()
                .any(|c| c.kind == ChangeKind::Removed && c.facet == Facet::Relationship)
        );
    }

    #[test]
    fn a_new_routine_is_reported() {
        let before = model();
        let mut after = before.clone();
        after.facets.routines.push(Routine {
            pattern: "running".to_owned(),
            schedule: "seen on 5 of 10 day(s)".to_owned(),
            confidence: 0.5,
            evidence: vec![MemoryId::new(1, [1u8; 10])],
        });

        let d = diff(&before, &after);
        let change = d
            .changes
            .iter()
            .find(|c| c.facet == Facet::Routine)
            .expect("a routine change");
        assert_eq!(change.kind, ChangeKind::Added);
        assert!(change.description.contains("running"));
    }

    /// Voice changes are measured over the whole corpus, so there is no honest
    /// subset of memories to name. An arbitrary sample would look like evidence
    /// and would not be.
    #[test]
    fn a_voice_change_claims_no_evidence_it_does_not_have() {
        let before = model();
        let mut after = before.clone();
        after.facets.voice.register.formality = before.facets.voice.register.formality + 0.4;

        let d = diff(&before, &after);
        let change = d
            .changes
            .iter()
            .find(|c| c.facet == Facet::Voice)
            .expect("a voice change");
        assert!(change.caused_by.is_empty());
        assert!(change.description.contains("formally") || change.description.contains("casually"));
    }

    /// The descriptions are the review surface, so they must read as sentences
    /// rather than as field dumps.
    #[test]
    fn descriptions_are_readable_by_a_non_developer() {
        let mut before = model();
        before
            .facets
            .opinions
            .push(stance("remote work", "prefers it", 0.8));
        let mut after = before.clone();
        after.facets.opinions[0].position = "dislikes it".to_owned();
        after.facets.routines.push(Routine {
            pattern: "running".to_owned(),
            schedule: String::new(),
            confidence: 0.5,
            evidence: vec![MemoryId::new(1, [1u8; 10])],
        });

        for change in &diff(&before, &after).changes {
            assert!(!change.description.is_empty());
            assert!(
                !change.description.contains('{') && !change.description.contains("Some("),
                "`{}` reads like a debug dump",
                change.description
            );
            assert!(
                change
                    .description
                    .chars()
                    .next()
                    .is_some_and(char::is_lowercase),
                "`{}` should read as a clause",
                change.description
            );
        }
    }

    #[test]
    fn a_small_diff_does_not_warrant_review() {
        let before = model();
        let mut after = before.clone();
        after.facets.routines.push(Routine {
            pattern: "running".to_owned(),
            schedule: String::new(),
            confidence: 0.5,
            evidence: vec![MemoryId::new(1, [1u8; 10])],
        });
        assert!(!warrants_review(&diff(&before, &after)));
    }

    #[test]
    fn many_changes_warrant_review() {
        let before = model();
        let mut after = before.clone();
        for n in 0..6 {
            after.facets.routines.push(Routine {
                pattern: format!("routine {n}"),
                schedule: String::new(),
                confidence: 0.5,
                evidence: vec![MemoryId::new(1, [1u8; 10])],
            });
        }
        assert!(warrants_review(&diff(&before, &after)));
    }
}
