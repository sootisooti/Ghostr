//! Applying pseudonyms and strips to a payload.
//!
//! # What this achieves, and what it does not
//!
//! Pseudonymisation is **not** anonymisation. "Person A, seen daily, warm
//! valence, discussed a wedding" plus any outside knowledge re-identifies
//! quickly, and writing style alone is close to unique across enough text. This
//! layer raises the cost of casual correlation; it does not defeat a motivated
//! analyst (THREAT_MODEL §T3).
//!
//! What it *does* guarantee is that the mapping never leaves the device, and
//! that a failure to apply it fails the request rather than sending the real
//! name.

use ghostr_core::ids::EntityId;
use ghostr_core::memory::Span;

use crate::redact::{PseudonymMapping, RedactionPlan, Redactor};

/// A name the redactor knows how to replace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KnownEntity {
    /// Which entity.
    pub id: EntityId,
    /// The real name. Never leaves this process.
    pub name: String,
    /// What it becomes.
    pub pseudonym: String,
}

/// Replaces known entity names with their pseudonyms.
#[derive(Debug, Clone, Default)]
pub struct EntityRedactor {
    known: Vec<KnownEntity>,
}

impl EntityRedactor {
    /// A redactor over a known set of entities.
    ///
    /// Longest name first, so "Nan Somsri" is replaced before "Nan" and a
    /// surname is not left stranded next to a pseudonym.
    #[must_use]
    pub fn new(mut known: Vec<KnownEntity>) -> Self {
        known.sort_by(|a, b| {
            b.name
                .len()
                .cmp(&a.name.len())
                .then_with(|| a.name.cmp(&b.name))
        });
        Self { known }
    }

    /// How many entities this redactor can replace.
    #[must_use]
    pub fn len(&self) -> usize {
        self.known.len()
    }

    /// Whether it knows nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.known.is_empty()
    }
}

impl Redactor for EntityRedactor {
    fn plan(&self, text: &str, entities: &[EntityId]) -> crate::Result<RedactionPlan> {
        let mut pseudonymise: Vec<PseudonymMapping> = Vec::new();
        // Regions already claimed by a longer name. `self.known` is sorted
        // longest-first, so the most specific match wins the region and shorter
        // names that overlap it are skipped.
        //
        // Without this, "Nan Somsri" and "Nan" both match the same text and the
        // two overlapping replacements interleave into "Person Ason B" — a
        // corrupted payload sent to a provider, which is worse than either name
        // alone.
        let mut claimed: Vec<(u32, u32)> = Vec::new();

        for entity in &self.known {
            let spans: Vec<Span> = find_all(text, &entity.name)
                .into_iter()
                .filter(|s| !claimed.iter().any(|(cs, ce)| s.start < *ce && *cs < s.end))
                .collect();
            if spans.is_empty() {
                continue;
            }
            claimed.extend(spans.iter().map(|s| (s.start, s.end)));
            pseudonymise.push(PseudonymMapping {
                entity: entity.id,
                pseudonym: entity.pseudonym.clone(),
                spans,
            });
        }

        // An entity the caller says is in this payload but whose name we cannot
        // resolve is a hard failure. Proceeding would send a real name to a
        // provider under the belief that it had been replaced, which is the
        // exact failure this layer exists to prevent.
        for wanted in entities {
            if !self.known.iter().any(|k| &k.id == wanted) {
                return Err(crate::Error::EgressDenied {
                    reason: crate::egress::DenyReason::PseudonymisationFailed,
                });
            }
        }

        Ok(RedactionPlan {
            pseudonymise,
            strip: Vec::new(),
            truncated: false,
        })
    }

    fn apply(&self, text: &str, plan: &RedactionPlan) -> crate::Result<String> {
        // Collect every edit, then apply back to front so earlier offsets stay
        // valid as the string shrinks or grows.
        let mut edits: Vec<(Span, &str)> = Vec::new();
        for mapping in &plan.pseudonymise {
            for span in &mapping.spans {
                edits.push((*span, mapping.pseudonym.as_str()));
            }
        }
        for span in &plan.strip {
            edits.push((*span, "[redacted]"));
        }
        edits.sort_by_key(|(s, _)| core::cmp::Reverse(s.start));

        let mut out = text.to_owned();
        for (span, replacement) in edits {
            let start = usize::try_from(span.start).unwrap_or(usize::MAX);
            let end = usize::try_from(span.end).unwrap_or(usize::MAX);
            if start > end || end > out.len() {
                return Err(crate::Error::EgressDenied {
                    reason: crate::egress::DenyReason::PseudonymisationFailed,
                });
            }
            // Splitting a multi-byte character would corrupt the payload rather
            // than redact it, so refuse instead.
            if !out.is_char_boundary(start) || !out.is_char_boundary(end) {
                return Err(crate::Error::EgressDenied {
                    reason: crate::egress::DenyReason::PseudonymisationFailed,
                });
            }
            out.replace_range(start..end, replacement);
        }
        Ok(out)
    }
}

/// Every occurrence of `needle` in `haystack`, case-insensitively, on word
/// boundaries.
///
/// Word boundaries so that "Nan" does not rewrite the middle of "Nanjing", and
/// case-insensitive because a journal writes "nan" and "Nan" interchangeably.
fn find_all(haystack: &str, needle: &str) -> Vec<Span> {
    if needle.is_empty() {
        return Vec::new();
    }
    let hay_lower = haystack.to_lowercase();
    let needle_lower = needle.to_lowercase();
    // Lowercasing can change byte length for some scripts, which would make the
    // offsets wrong. Fall back to a case-sensitive scan when that happens rather
    // than producing spans that slice the wrong bytes.
    let lower_is_aligned = hay_lower.len() == haystack.len();
    let subject = if lower_is_aligned {
        hay_lower.as_str()
    } else {
        haystack
    };
    let pattern = if lower_is_aligned {
        needle_lower.as_str()
    } else {
        needle
    };

    let mut out = Vec::new();
    let mut from = 0usize;
    while let Some(rel) = subject[from..].find(pattern) {
        let start = from + rel;
        let end = start + pattern.len();
        let before_ok = start == 0
            || !subject[..start]
                .chars()
                .next_back()
                .is_some_and(char::is_alphanumeric);
        let after_ok = end == subject.len()
            || !subject[end..]
                .chars()
                .next()
                .is_some_and(char::is_alphanumeric);
        if before_ok && after_ok {
            out.push(Span {
                start: u32::try_from(start).unwrap_or(u32::MAX),
                end: u32::try_from(end).unwrap_or(u32::MAX),
            });
        }
        from = end;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn redactor() -> EntityRedactor {
        EntityRedactor::new(vec![
            KnownEntity {
                id: EntityId::new(1, [1u8; 10]),
                name: "Nan".to_owned(),
                pseudonym: "Person A".to_owned(),
            },
            KnownEntity {
                id: EntityId::new(2, [2u8; 10]),
                name: "Nan Somsri".to_owned(),
                pseudonym: "Person B".to_owned(),
            },
        ])
    }

    fn redact(text: &str) -> String {
        let r = redactor();
        let plan = r.plan(text, &[]).expect("plan");
        r.apply(text, &plan).expect("apply")
    }

    #[test]
    fn names_become_pseudonyms() {
        assert_eq!(
            redact("coffee with Nan today"),
            "coffee with Person A today"
        );
    }

    #[test]
    fn matching_is_case_insensitive() {
        assert_eq!(redact("saw nan and NAN"), "saw Person A and Person A");
    }

    /// The longest name wins the region, or the two replacements interleave.
    ///
    /// Regression: "Nan Somsri" and "Nan" both matched and produced overlapping
    /// spans, splicing into "Person Ason B".
    #[test]
    fn the_longer_name_claims_the_region() {
        assert_eq!(redact("dinner with Nan Somsri"), "dinner with Person B");
    }

    /// Both names present separately must each still resolve.
    #[test]
    fn overlap_handling_does_not_swallow_a_separate_mention() {
        assert_eq!(
            redact("Nan Somsri called, then Nan wrote"),
            "Person B called, then Person A wrote"
        );
    }

    /// No two spans in a plan may overlap, whatever the entity list looks like.
    #[test]
    fn a_plan_never_contains_overlapping_spans() {
        let r = redactor();
        let plan = r
            .plan("Nan Somsri and Nan and Nan Somsri again", &[])
            .expect("plan");
        let mut spans: Vec<_> = plan
            .pseudonymise
            .iter()
            .flat_map(|m| m.spans.iter().copied())
            .collect();
        spans.sort_by_key(|s| s.start);
        for pair in spans.windows(2) {
            assert!(pair[0].end <= pair[1].start, "overlapping spans: {pair:?}");
        }
    }

    /// "Nan" must not rewrite the middle of "Nanjing".
    #[test]
    fn matching_respects_word_boundaries() {
        assert_eq!(redact("flew to Nanjing"), "flew to Nanjing");
        assert_eq!(redact("Nan's flat"), "Person A's flat");
    }

    #[test]
    fn a_name_that_is_absent_produces_no_mapping() {
        let r = redactor();
        let plan = r.plan("nothing personal here", &[]).expect("plan");
        assert!(plan.pseudonymise.is_empty());
    }

    /// Failing to resolve an entity must fail the request, never send the name.
    #[test]
    fn an_unresolvable_entity_fails_closed() {
        let r = redactor();
        let unknown = EntityId::new(99, [9u8; 10]);
        let err = r.plan("text", &[unknown]).expect_err("must fail");
        assert!(matches!(
            err,
            crate::Error::EgressDenied {
                reason: crate::egress::DenyReason::PseudonymisationFailed
            }
        ));
    }

    #[test]
    fn multiple_occurrences_are_all_replaced() {
        assert_eq!(
            redact("Nan called, then Nan wrote, then Nan left"),
            "Person A called, then Person A wrote, then Person A left"
        );
    }

    /// The plan must never carry the real name — it is logged, and the audit log
    /// must not become a second copy of the entity table.
    #[test]
    fn the_plan_does_not_contain_real_names() {
        let r = redactor();
        let plan = r.plan("coffee with Nan", &[]).expect("plan");
        let rendered = format!("{plan:?}");
        assert!(
            !rendered.contains("Nan"),
            "the plan leaked a real name: {rendered}"
        );
        assert!(rendered.contains("Person A"));
    }

    #[test]
    fn non_ascii_text_is_not_corrupted() {
        let r = EntityRedactor::new(vec![KnownEntity {
            id: EntityId::new(1, [1u8; 10]),
            name: "แนน".to_owned(),
            pseudonym: "Person A".to_owned(),
        }]);
        let text = "ไปกินข้าวกับ แนน วันนี้";
        let plan = r.plan(text, &[]).expect("plan");
        let out = r.apply(text, &plan).expect("apply");
        assert!(out.contains("Person A"), "got: {out}");
        assert!(!out.contains("แนน"));
        // Still valid UTF-8 and the rest of the sentence intact.
        assert!(out.contains("ไปกินข้าวกับ"));
    }

    #[test]
    fn a_span_past_the_end_is_refused_rather_than_panicking() {
        let r = redactor();
        let plan = RedactionPlan {
            pseudonymise: vec![PseudonymMapping {
                entity: EntityId::new(1, [1u8; 10]),
                pseudonym: "Person A".to_owned(),
                spans: vec![Span {
                    start: 0,
                    end: 9_999,
                }],
            }],
            strip: Vec::new(),
            truncated: false,
        };
        assert!(r.apply("short", &plan).is_err());
    }
}
