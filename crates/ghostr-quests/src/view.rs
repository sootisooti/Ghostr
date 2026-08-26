//! What a quest may show before its verdict.
//!
//! Several [`QuestKind`] variants carry the ghost's committed answer, and for
//! some of them that answer *is* the question while for others it is the answer
//! key. Getting that distinction wrong leaks the thing the commitment exists to
//! protect (SPEC I6).
//!
//! So the decision is made once, here, and every surface renders the result.
//! Two renderers each reading a `QuestKind` and deciding for themselves is how
//! an answer key escapes from whichever one got it wrong — and the one that got
//! it wrong is always the newer one, written by someone who did not know the
//! rule existed.

use ghostr_core::quest::{Choice, QuestKind};

/// A quest in the form it may be shown in before a verdict.
///
/// There is deliberately no variant carrying `ghost_choice` or
/// `ghost_completion`. The withholding is structural rather than a rule a
/// renderer has to remember: a surface cannot print what it was never handed.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Presented {
    /// A claim to confirm or deny. The claim is the question.
    Claim {
        /// What the ghost asserts.
        text: String,
        /// The day or horizon it is about, rendered.
        when: String,
    },
    /// The ghost's own words, shown because they *are* the question.
    Assertion {
        /// What the ghost was asked.
        prompt: String,
        /// What it claims the user would say.
        ghost_answer: String,
    },
    /// Two options. Which one the ghost picked stays sealed.
    Choice {
        /// The first option.
        a: String,
        /// The second option.
        b: String,
    },
    /// A sentence with a hole in it. The completion stays sealed.
    Gap {
        /// Text before the hole.
        before: String,
        /// Text after the hole.
        after: String,
    },
    /// A kind this build does not know how to show.
    ///
    /// [`QuestKind`] is `#[non_exhaustive]`. Rendering an unknown variant by
    /// guessing at its fields is how an answer key leaks, so an unknown kind
    /// shows nothing at all and the user is told to void it.
    Unrenderable,
}

/// Turns a quest into the form a user may see.
#[must_use]
pub fn present(kind: &QuestKind) -> Presented {
    match kind {
        QuestKind::VoiceProbe {
            prompt,
            ghost_answer,
        } => Presented::Assertion {
            prompt: prompt.clone(),
            ghost_answer: ghost_answer.clone(),
        },
        QuestKind::Counterfactual {
            scenario,
            ghost_answer,
        } => Presented::Assertion {
            prompt: scenario.clone(),
            ghost_answer: ghost_answer.clone(),
        },
        QuestKind::FactRecall { claim, as_of } => Presented::Claim {
            text: claim.clone(),
            when: as_of.to_string(),
        },
        QuestKind::Prediction { claim, horizon } => Presented::Claim {
            text: claim.clone(),
            when: horizon.to_string(),
        },
        // `ghost_choice` is not read. Reading it here is the whole mistake this
        // module exists to make impossible.
        QuestKind::Preference { a, b, .. } => Presented::Choice {
            a: a.clone(),
            b: b.clone(),
        },
        QuestKind::Cloze {
            context, redacted, ..
        } => split_at_gap(context, redacted.start as usize, redacted.end as usize).map_or(
            Presented::Unrenderable,
            |(before, after)| Presented::Gap { before, after },
        ),
        _ => Presented::Unrenderable,
    }
}

/// Splits a sentence around the redacted span.
///
/// Returns `None` for a span that does not land on character boundaries or runs
/// past the end. That means the row is damaged, and showing the whole sentence
/// would reveal the very word the quest asks for — so it shows nothing.
fn split_at_gap(context: &str, start: usize, end: usize) -> Option<(String, String)> {
    if start > end || end > context.len() {
        return None;
    }
    if !context.is_char_boundary(start) || !context.is_char_boundary(end) {
        return None;
    }
    Some((context[..start].to_owned(), context[end..].to_owned()))
}

/// Which option the ghost picked, for use *after* a verdict is recorded.
///
/// Separate from [`present`] and named so that calling it before a verdict
/// reads as the mistake it would be.
#[must_use]
pub fn revealed_choice(kind: &QuestKind) -> Option<Choice> {
    match kind {
        QuestKind::Preference { ghost_choice, .. } => Some(*ghost_choice),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use ghostr_core::memory::Span;

    use super::*;

    fn rendered(p: &Presented) -> String {
        match p {
            Presented::Claim { text, when } => format!("{when} {text}"),
            Presented::Assertion {
                prompt,
                ghost_answer,
            } => format!("{prompt} {ghost_answer}"),
            Presented::Choice { a, b } => format!("{a} {b}"),
            Presented::Gap { before, after } => format!("{before} {after}"),
            Presented::Unrenderable => String::new(),
        }
    }

    /// I6 on the reveal side: a kind whose answer *is* its question must show
    /// that answer, or the user is being asked to judge something they cannot
    /// read.
    #[test]
    fn a_kind_that_asserts_shows_what_it_asserts() {
        let date = chrono::NaiveDate::from_ymd_opt(2026, 3, 1).expect("date");
        let kinds = [
            QuestKind::VoiceProbe {
                prompt: "on deadlines".to_owned(),
                ghost_answer: "I'd rather ship late than ship wrong".to_owned(),
            },
            QuestKind::Counterfactual {
                scenario: "offered the job".to_owned(),
                ghost_answer: "you'd ask for a week".to_owned(),
            },
            QuestKind::FactRecall {
                claim: "you saw Nan on Tuesday".to_owned(),
                as_of: date,
            },
            QuestKind::Prediction {
                claim: "you'll skip the gym".to_owned(),
                horizon: date,
            },
        ];

        for kind in &kinds {
            assert!(
                kind.reveals_answer_upfront(),
                "{} asserts something; it cannot withhold it",
                kind.variant_name()
            );
            assert!(
                rendered(&present(kind)).contains(kind.committed_answer()),
                "{} withheld the claim it is asking about",
                kind.variant_name()
            );
        }
    }

    /// I6 on the withholding side, for the one kind where the answer is a
    /// separate string from the question.
    ///
    /// `Preference` is the other withholding kind, but its secret is *which*
    /// option rather than the option text — both options must be printed. That
    /// half is covered by `a_preference_shows_both_options_and_neither_pick`,
    /// which is the sharper test: it asserts the two renderings are
    /// byte-identical, so the pick cannot be recovered by comparing them.
    #[test]
    fn a_cloze_never_shows_the_word_it_asks_for() {
        let kind = QuestKind::Cloze {
            context: "I always order a flat white after a long day".to_owned(),
            redacted: Span { start: 17, end: 27 },
            ghost_completion: "flat white".to_owned(),
        };
        assert!(!kind.reveals_answer_upfront());
        assert!(!rendered(&present(&kind)).contains(kind.committed_answer()));
    }

    #[test]
    fn a_preference_shows_both_options_and_neither_pick() {
        let a = present(&QuestKind::Preference {
            a: "coffee".to_owned(),
            b: "tea".to_owned(),
            ghost_choice: Choice::A,
        });
        let b = present(&QuestKind::Preference {
            a: "coffee".to_owned(),
            b: "tea".to_owned(),
            ghost_choice: Choice::B,
        });
        // Identical whichever way the ghost went: the pick is not in the output
        // at all, so it cannot be recovered by comparing two renderings.
        assert_eq!(a, b);
        assert_eq!(
            a,
            Presented::Choice {
                a: "coffee".to_owned(),
                b: "tea".to_owned()
            }
        );
    }

    #[test]
    fn a_cloze_shows_the_sentence_around_the_hole() {
        let shown = present(&QuestKind::Cloze {
            context: "I always order a flat white after a long day".to_owned(),
            redacted: Span { start: 17, end: 27 },
            ghost_completion: "flat white".to_owned(),
        });
        assert_eq!(
            shown,
            Presented::Gap {
                before: "I always order a ".to_owned(),
                after: " after a long day".to_owned()
            }
        );
    }

    /// A damaged span must show nothing rather than the whole sentence, which
    /// would contain the word being asked for.
    #[test]
    fn a_damaged_span_shows_nothing() {
        for span in [
            Span { start: 9, end: 3 },
            Span {
                start: 0,
                end: 9_999,
            },
        ] {
            assert_eq!(
                present(&QuestKind::Cloze {
                    context: "I always order a flat white".to_owned(),
                    redacted: span,
                    ghost_completion: "flat white".to_owned(),
                }),
                Presented::Unrenderable
            );
        }
    }

    /// A span landing mid-character would panic on a naive slice, and the
    /// obvious "fix" — widen to the nearest boundary — reveals part of the
    /// answer.
    #[test]
    fn a_span_inside_a_multibyte_character_shows_nothing() {
        assert_eq!(
            present(&QuestKind::Cloze {
                context: "ผมชอบกาแฟมากกว่าชา".to_owned(),
                redacted: Span { start: 1, end: 4 },
                ghost_completion: "กาแฟ".to_owned(),
            }),
            Presented::Unrenderable
        );
    }
}
