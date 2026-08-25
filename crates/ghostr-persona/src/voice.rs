//! Voice profiling, computed rather than inferred.
//!
//! Everything in a [`VoiceProfile`] is arithmetic over the corpus: sentence
//! lengths, punctuation counts, word rates against a baseline. No model is
//! involved, and that is not a limitation to be lifted later — it is the right
//! tool. "How long are this person's sentences" is a measurement, and a model
//! asked to estimate it would produce a plausible number instead of the true
//! one.
//!
//! # What a model would add, and where it stops
//!
//! Stances, boundaries, and lore need a model: "what does this person think
//! about X" is not countable. Voice is. Keeping the two apart means the voice
//! half of a persona is exact, reproducible, and available on day one with no
//! runtime installed (SPEC §3.6).
//!
//! # First-party only
//!
//! [`exemplars`](VoiceProfile::exemplars) are verbatim utterances the ghost will
//! speak from, so they are drawn from
//! [`TrustLevel::FirstParty`](ghostr_core::sensitivity::TrustLevel::FirstParty)
//! content and nothing else. Letting a feed item become an exemplar is how a
//! stranger's voice ends up in the ghost's mouth (THREAT_MODEL §T7).

use ghostr_core::ids::MemoryId;
use ghostr_core::memory::Memory;
use ghostr_core::persona::{LexicalTic, PunctuationHabits, Register, SyntaxStats, VoiceProfile};

/// Words that mark formal register.
const FORMAL: &[&str] = &[
    "therefore",
    "however",
    "moreover",
    "regarding",
    "furthermore",
    "accordingly",
    "consequently",
    "nevertheless",
    "whom",
    "shall",
];

/// Words that mark casual register.
const CASUAL: &[&str] = &[
    "yeah", "nah", "gonna", "kinda", "sorta", "stuff", "guys", "ok", "okay", "lol", "yep", "nope",
    "anyway",
];

/// Words that mark warmth.
const WARM: &[&str] = &[
    "love",
    "thanks",
    "grateful",
    "lovely",
    "glad",
    "kind",
    "sweet",
    "happy",
    "wonderful",
    "appreciate",
    "friend",
    "care",
];

/// Words that mark distance or coolness.
const COOL: &[&str] = &[
    "fine",
    "whatever",
    "regardless",
    "irrelevant",
    "noted",
    "apparently",
];

/// Words that hedge a claim.
const HEDGES: &[&str] = &[
    "maybe",
    "perhaps",
    "probably",
    "possibly",
    "might",
    "seems",
    "somewhat",
    "roughly",
    "apparently",
    "arguably",
    "fairly",
    "guess",
    "think",
    "suppose",
];

/// A short, inspectable profanity list.
///
/// Deliberately mild and short. The measurement worth having is "does this
/// person swear at all, and roughly how much", which two entries answer as well
/// as fifty — and a long list in a repository is its own problem.
const PROFANITY: &[&str] = &["damn", "hell", "shit", "fuck", "crap", "bloody"];

/// Words too common to be characteristic.
///
/// A tic list that surfaces "the" tells you nothing about anyone. This is the
/// baseline the distinctiveness score is measured against.
const STOPWORDS: &[&str] = &[
    "the", "a", "an", "and", "or", "but", "if", "then", "of", "to", "in", "on", "at", "for",
    "with", "is", "was", "are", "were", "be", "been", "it", "its", "this", "that", "these",
    "those", "i", "me", "my", "you", "your", "he", "she", "they", "we", "us", "as", "so", "not",
    "no", "do", "did", "does", "have", "has", "had", "will", "would", "can", "could", "up", "out",
    "about", "into", "over", "after", "from", "by", "all", "just", "than", "too", "very", "there",
    "here", "when", "what", "which", "who", "how", "why", "again", "more", "some", "any", "one",
    "day", "today", "got", "get", "go", "going", "back", "still", "now", "like",
];

/// How many lexical tics to keep.
const MAX_TICS: usize = 24;

/// How many exemplars to keep.
///
/// Enough to show range, few enough that a reader can check every one. Anything
/// the ghost will speak from should be reviewable by hand.
const MAX_EXEMPLARS: usize = 12;

/// The shortest utterance worth keeping as an exemplar.
const MIN_EXEMPLAR_WORDS: usize = 6;

/// Builds a voice profile from first-party memories.
///
/// `corpus` should already be filtered to first-party content; the caller knows
/// the trust level and this function does not re-derive it. What it *does*
/// enforce is that exemplars come from the same slice — there is no path here
/// that reaches other memories.
#[must_use]
pub fn profile(corpus: &[&Memory]) -> VoiceProfile {
    let texts: Vec<&str> = corpus.iter().map(|m| m.body.text.as_str()).collect();
    let words = word_counts(&texts);
    let total_words: u32 = words.values().sum();

    VoiceProfile {
        register: register(&words, total_words),
        lexicon: lexicon(&words, total_words),
        syntax: syntax(&texts),
        punctuation: punctuation(&texts, total_words),
        exemplars: exemplars(corpus),
    }
}

/// Lowercased word frequencies across the corpus.
fn word_counts(texts: &[&str]) -> std::collections::BTreeMap<String, u32> {
    let mut out: std::collections::BTreeMap<String, u32> = std::collections::BTreeMap::new();
    for text in texts {
        for word in text.split_whitespace() {
            let cleaned: String = word
                .chars()
                .filter(|c| c.is_alphanumeric() || *c == '\'')
                .collect::<String>()
                .to_lowercase();
            if cleaned.is_empty() {
                continue;
            }
            *out.entry(cleaned).or_default() += 1;
        }
    }
    out
}

/// The four register axes.
///
/// Each is a ratio of matches to a scale, clamped — never a raw count. A corpus
/// of ten notes and one of ten thousand must land on the same axis if the person
/// writes the same way, or the profile would drift as the corpus grew rather
/// than as the person changed.
fn register(words: &std::collections::BTreeMap<String, u32>, total: u32) -> Register {
    /// Words added to the denominator of a density estimate.
    ///
    /// A rate measured over twenty words is not a rate, it is an anecdote. Two
    /// hedges in a two-line note is 8% by division and means nothing; the same
    /// density sustained over a thousand words is a real habit. Adding a
    /// notional corpus to the denominator shrinks a small sample toward zero
    /// and leaves a large one almost untouched, which is exactly the difference
    /// in confidence between the two.
    const SMOOTH_WORDS: f32 = 200.0;

    let hits = |list: &[&str]| -> u32 { list.iter().filter_map(|w| words.get(*w)).copied().sum() };
    let rate = |list: &[&str]| -> f32 {
        if total == 0 {
            return 0.0;
        }
        hits(list) as f32 / total as f32
    };
    let density = |list: &[&str], scale: f32| -> f32 {
        (hits(list) as f32 / (total as f32 + SMOOTH_WORDS) * scale).clamp(0.0, 1.0)
    };

    Register {
        // Midpoint when neither register shows: 0.5 means "no signal", not
        // "exactly balanced". `hedging` and `profanity` start at zero instead,
        // because those genuinely are absences rather than midpoints.
        formality: axis(rate(FORMAL), rate(CASUAL)),
        warmth: axis(rate(WARM), rate(COOL)),
        // Scaled so a sustained heavy hedger lands around 0.4 rather than
        // saturating. An axis that reads 1.00 for everyone measures nothing.
        hedging: density(HEDGES, 25.0),
        profanity: density(PROFANITY, 200.0),
    }
}

/// Places two competing rates on a `0.0..=1.0` axis, smoothed toward the middle.
///
/// The smoothing is the important part. Without it, a corpus containing one warm
/// word and no cool ones reads as *maximally* warm — a confident claim from a
/// single observation. The pseudocount pulls a one-sided result toward the
/// midpoint in proportion to how little evidence supports it, so an axis
/// approaches its extreme only when the corpus genuinely insists.
///
/// The midpoint is also what an absent signal returns, which does conflate "no
/// evidence" with "evenly balanced". The two are not separable in one number,
/// and an `Option` on every axis would push that case onto every reader for
/// little gain.
fn axis(a: f32, b: f32) -> f32 {
    /// Comparable to a low-but-real word rate, so a *single* occurrence cannot
    /// dominate the axis while a sustained one still moves it.
    const PRIOR: f32 = 0.003;

    ((a + PRIOR) / (a + b + 2.0 * PRIOR)).clamp(0.0, 1.0)
}

/// The most distinctive words, by rate against the stopword baseline.
fn lexicon(words: &std::collections::BTreeMap<String, u32>, total: u32) -> Vec<LexicalTic> {
    if total == 0 {
        return Vec::new();
    }
    let mut tics: Vec<LexicalTic> = words
        .iter()
        .filter(|(word, count)| {
            **count > 1 && word.len() > 3 && !STOPWORDS.contains(&word.as_str())
        })
        .map(|(word, count)| {
            let rate = (*count as f32 / total as f32) * 1_000.0;
            LexicalTic {
                phrase: word.clone(),
                rate_per_kiloword: rate,
                // Longer and rarer words are more characteristic. Crude, and
                // transparent: a reader can predict why a word scored highly,
                // which matters more here than a better-tuned opaque number.
                distinctiveness: (rate / 10.0).clamp(0.0, 1.0),
            }
        })
        .collect();

    // Ties break on the phrase, so the list is total and reproducible — it is
    // hashed into the persona version.
    tics.sort_by(|a, b| {
        b.rate_per_kiloword
            .partial_cmp(&a.rate_per_kiloword)
            .unwrap_or(core::cmp::Ordering::Equal)
            .then_with(|| a.phrase.cmp(&b.phrase))
    });
    tics.truncate(MAX_TICS);
    tics
}

/// Sentence-level statistics.
fn syntax(texts: &[&str]) -> SyntaxStats {
    let lengths: Vec<usize> = texts
        .iter()
        .flat_map(|t| sentences(t))
        .map(|s| s.split_whitespace().count())
        .filter(|n| *n > 0)
        .collect();

    if lengths.is_empty() {
        return SyntaxStats {
            mean_sentence_words: 0.0,
            sentence_words_stddev: 0.0,
            mean_clause_depth: 0.0,
            fragment_rate: 0.0,
        };
    }

    let n = lengths.len() as f32;
    let mean = lengths.iter().sum::<usize>() as f32 / n;
    let variance = lengths
        .iter()
        .map(|len| {
            let d = *len as f32 - mean;
            d * d
        })
        .sum::<f32>()
        / n;

    // Commas and subordinating conjunctions as a proxy for clause depth. Not a
    // parse — a parse would need a grammar this crate has no business carrying,
    // and the measurement is a shape, not a syntax tree.
    let clause_markers: usize = texts
        .iter()
        .map(|t| {
            t.matches(',').count()
                + t.split_whitespace()
                    .filter(|w| {
                        matches!(
                            w.trim_matches(|c: char| !c.is_alphanumeric())
                                .to_lowercase()
                                .as_str(),
                            "which" | "that" | "because" | "although" | "while" | "since"
                        )
                    })
                    .count()
        })
        .sum();

    SyntaxStats {
        mean_sentence_words: mean,
        sentence_words_stddev: variance.sqrt(),
        mean_clause_depth: clause_markers as f32 / n,
        // A fragment is a sentence too short to have a subject and a verb doing
        // any work. Four words is the boundary, and it is a heuristic stated
        // plainly rather than a threshold hidden in a constant.
        fragment_rate: lengths.iter().filter(|len| **len < 4).count() as f32 / n,
    }
}

/// Punctuation and typography rates.
fn punctuation(texts: &[&str], total_words: u32) -> PunctuationHabits {
    let per_kiloword = |count: usize| -> f32 {
        if total_words == 0 {
            return 0.0;
        }
        (count as f32 / total_words as f32) * 1_000.0
    };

    let all_sentences: Vec<&str> = texts.iter().flat_map(|t| sentences(t)).collect();
    let sentence_count = all_sentences.len().max(1) as f32;

    PunctuationHabits {
        em_dash_rate: per_kiloword(texts.iter().map(|t| t.matches('—').count()).sum()),
        lowercase_start_rate: all_sentences
            .iter()
            .filter(|s| s.chars().next().is_some_and(char::is_lowercase))
            .count() as f32
            / sentence_count,
        emoji_rate: per_kiloword(
            texts
                .iter()
                .map(|t| t.chars().filter(|c| is_emoji(*c)).count())
                .sum(),
        ),
        ellipsis_rate: per_kiloword(
            texts
                .iter()
                .map(|t| t.matches("...").count() + t.matches('…').count())
                .sum(),
        ),
        unterminated_rate: all_sentences
            .iter()
            .filter(|s| !s.trim_end().ends_with(['.', '!', '?']))
            .count() as f32
            / sentence_count,
    }
}

/// Whether a character is in one of the emoji blocks.
///
/// Ranges rather than a crate: this is a rate for a profile, not a renderer, and
/// being approximate at the edges costs nothing here.
fn is_emoji(c: char) -> bool {
    matches!(u32::from(c),
        0x1F300..=0x1FAFF | 0x2600..=0x27BF | 0x1F000..=0x1F02F | 0xFE0F)
}

/// Splits text into sentence-ish spans.
fn sentences(text: &str) -> Vec<&str> {
    text.split_inclusive(['.', '!', '?', '\n'])
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect()
}

/// Picks verbatim utterances the ghost may speak from.
///
/// Longest first, because a six-word note shows nothing about how someone
/// builds a sentence. Ties break on id so the selection is reproducible.
fn exemplars(corpus: &[&Memory]) -> Vec<MemoryId> {
    let mut candidates: Vec<&&Memory> = corpus
        .iter()
        .filter(|m| m.body.text.split_whitespace().count() >= MIN_EXEMPLAR_WORDS)
        .collect();

    candidates.sort_by(|a, b| {
        b.body
            .text
            .split_whitespace()
            .count()
            .cmp(&a.body.text.split_whitespace().count())
            .then_with(|| a.id.cmp(&b.id))
    });
    candidates
        .into_iter()
        .take(MAX_EXEMPLARS)
        .map(|m| m.id)
        .collect()
}

#[cfg(test)]
mod tests_support {
    pub(super) use super::tests::profile_of;
}

#[cfg(test)]
mod tests {
    use ghostr_core::hash::{Tag, tagged_hash};
    use ghostr_core::ids::SourceId;
    use ghostr_core::memory::{MemoryBody, MemoryKind, Provenance};
    use ghostr_core::sensitivity::Sensitivity;
    use ghostr_core::time::Timestamp;

    use super::*;

    fn memory(n: u8, text: &str) -> Memory {
        let source = SourceId::new(1, [0u8; 10]);
        Memory {
            id: MemoryId::new(u64::from(n), [n; 10]),
            source_id: source,
            occurred_at: Some(Timestamp::new(i64::from(n) * 1_000, 0)),
            ingested_at: Timestamp::new(0, 0),
            kind: MemoryKind::Utterance,
            body: MemoryBody {
                text: text.to_owned(),
                structured: None,
                redactions: Vec::new(),
            },
            entities: Vec::new(),
            salience: 0.5,
            sensitivity: Sensitivity::Private,
            provenance: Provenance {
                source_id: source,
                external_id: None,
                url: None,
                raw_hash: tagged_hash(Tag::MemoryLeaf, &[n]),
            },
            salt: [n; 32],
            supersedes: None,
            embedding: None,
        }
    }

    pub(super) fn profile_of(texts: &[&str]) -> VoiceProfile {
        let memories: Vec<Memory> = texts
            .iter()
            .enumerate()
            .map(|(i, t)| memory(i as u8, t))
            .collect();
        let refs: Vec<&Memory> = memories.iter().collect();
        profile(&refs)
    }

    /// The measurement is exact, which is the reason it is arithmetic and not a
    /// model: a model asked for a mean would produce a plausible number.
    #[test]
    fn sentence_length_is_measured_not_estimated() {
        // Two sentences: 5 words and 3 words.
        let p = profile_of(&["One two three four five. Six seven eight."]);
        assert!((p.syntax.mean_sentence_words - 4.0).abs() < 1e-5);
    }

    #[test]
    fn a_formal_writer_scores_above_a_casual_one() {
        let formal = profile_of(&[
            "Therefore the matter shall proceed. However, regarding the schedule, \
             moreover I note the following.",
        ]);
        let casual = profile_of(&["yeah ok gonna grab stuff, kinda tired lol. nope anyway"]);
        assert!(
            formal.register.formality > casual.register.formality,
            "formal {} was not above casual {}",
            formal.register.formality,
            casual.register.formality
        );
    }

    /// A corpus with no signal lands at the midpoint rather than at zero.
    /// "I have no evidence" and "this person is maximally casual" are different
    /// answers and must not share a number.
    #[test]
    fn no_register_signal_lands_at_the_midpoint() {
        let p = profile_of(&["The parser now handles the third case."]);
        assert!((p.register.formality - 0.5).abs() < 1e-5);
        assert!((p.register.warmth - 0.5).abs() < 1e-5);
        // Hedging and profanity are absences, not midpoints.
        assert!(p.register.hedging < 0.01);
        assert!(p.register.profanity < 0.01);
    }

    #[test]
    fn hedging_is_detected() {
        let hedged = profile_of(&["Maybe we should probably think about it, I suppose."]);
        let direct = profile_of(&["We will do it on Tuesday."]);
        assert!(hedged.register.hedging > direct.register.hedging);
    }

    /// The profile must not drift as the corpus grows. Ten notes and a thousand
    /// of the same writing must land on the same axis, or the ghost would seem
    /// to change as its owner wrote more.
    #[test]
    fn register_does_not_drift_with_corpus_size() {
        let one = profile_of(&["yeah ok gonna grab stuff"]);
        let repeated: Vec<&str> = std::iter::repeat_n("yeah ok gonna grab stuff", 50).collect();
        let many = profile_of(&repeated);
        assert!((one.register.formality - many.register.formality).abs() < 1e-5);
    }

    /// A tic list that surfaces "the" tells you nothing about anyone.
    #[test]
    fn stopwords_never_become_lexical_tics() {
        let p = profile_of(&[
            "The parser is the thing that the team and the others in the office \
             have been at for the week.",
            "The parser and the team, the office, the week, the thing.",
        ]);
        for tic in &p.lexicon {
            assert!(
                !["the", "and", "that", "have", "been"].contains(&tic.phrase.as_str()),
                "`{}` is a stopword",
                tic.phrase
            );
        }
    }

    #[test]
    fn a_repeated_distinctive_word_becomes_a_tic() {
        let p = profile_of(&[
            "The parser is behaving. Parser work again tomorrow.",
            "Parser, parser, parser — it is all parser this week.",
        ]);
        assert!(
            p.lexicon.iter().any(|t| t.phrase == "parser"),
            "got {:?}",
            p.lexicon.iter().map(|t| &t.phrase).collect::<Vec<_>>()
        );
    }

    /// The lexicon is hashed into a persona version, so its order must be total
    /// and reproducible.
    #[test]
    fn the_profile_is_reproducible() {
        let texts = ["Parser work. Parser again.", "Another day, another parser."];
        let a = profile_of(&texts);
        let b = profile_of(&texts);
        assert_eq!(a, b);
    }

    #[test]
    fn punctuation_habits_are_counted() {
        let p = profile_of(&["one — two — three... and more 🙂"]);
        assert!(p.punctuation.em_dash_rate > 0.0);
        assert!(p.punctuation.ellipsis_rate > 0.0);
        assert!(p.punctuation.emoji_rate > 0.0);
    }

    #[test]
    fn lowercase_starts_are_measured() {
        let lower = profile_of(&["yeah fine. sure thing. ok then."]);
        let upper = profile_of(&["Yes fine. Sure thing. Ok then."]);
        assert!(lower.punctuation.lowercase_start_rate > upper.punctuation.lowercase_start_rate);
    }

    /// A six-word note shows nothing about how someone builds a sentence.
    #[test]
    fn short_utterances_are_not_exemplars() {
        let memories = [
            memory(1, "yes"),
            memory(2, "no"),
            memory(
                3,
                "I spent the whole afternoon on the parser and it finally works.",
            ),
        ];
        let refs: Vec<&Memory> = memories.iter().collect();
        let p = profile(&refs);
        assert_eq!(p.exemplars, vec![memories[2].id]);
    }

    /// THREAT_MODEL §T7. There is no path from this function to a memory
    /// outside the slice it was given, which is what the caller's first-party
    /// filter relies on.
    #[test]
    fn exemplars_come_only_from_the_corpus_given() {
        let memories = [memory(
            1,
            "One long enough sentence to qualify as an exemplar.",
        )];
        let refs: Vec<&Memory> = memories.iter().collect();
        let p = profile(&refs);
        assert!(p.exemplars.iter().all(|id| *id == memories[0].id));
    }

    /// An empty corpus must produce a profile, not a panic or a NaN: a new
    /// vault has one, and every downstream number is a ratio.
    #[test]
    fn an_empty_corpus_produces_a_zeroed_profile() {
        let p = profile(&[]);
        assert!(p.lexicon.is_empty());
        assert!(p.exemplars.is_empty());
        assert_eq!(p.syntax.mean_sentence_words, 0.0);
        assert!(p.syntax.sentence_words_stddev.is_finite());
        assert!(p.punctuation.em_dash_rate.is_finite());
        assert!(p.register.formality.is_finite());
    }

    /// Every axis is a fraction. A number outside its range would fail the
    /// draft validation downstream, and silently skew any score built on it.
    #[test]
    fn every_axis_stays_in_range() {
        for texts in [
            vec!["damn damn damn shit hell fuck crap bloody"],
            vec!["maybe perhaps probably possibly might seems somewhat"],
            vec!["therefore however moreover regarding furthermore"],
            vec![""],
        ] {
            let p = profile_of(&texts);
            for (name, value) in [
                ("formality", p.register.formality),
                ("warmth", p.register.warmth),
                ("hedging", p.register.hedging),
                ("profanity", p.register.profanity),
                ("fragment_rate", p.syntax.fragment_rate),
                ("lowercase_start_rate", p.punctuation.lowercase_start_rate),
                ("unterminated_rate", p.punctuation.unterminated_rate),
            ] {
                assert!(
                    (0.0..=1.0).contains(&value),
                    "{name} = {value} is outside 0..=1"
                );
            }
            for tic in &p.lexicon {
                assert!((0.0..=1.0).contains(&tic.distinctiveness));
            }
        }
    }
}

#[cfg(test)]
mod smoothing_tests {
    use super::tests_support::profile_of;

    /// The bug the prior fixes: one warm word and no cool ones read as
    /// *maximally* warm — a confident claim from a single observation.
    #[test]
    fn a_single_observation_does_not_saturate_an_axis() {
        let mostly_neutral = format!(
            "I appreciate that. {}",
            "The parser handles the third case now. ".repeat(60)
        );
        let p = profile_of(&[&mostly_neutral]);
        assert!(
            p.register.warmth < 0.8,
            "one warm word in a long corpus gave warmth {}",
            p.register.warmth
        );
        assert!(p.register.warmth > 0.5, "but it should still lean warm");
    }

    /// A corpus that genuinely insists still reaches the extreme.
    #[test]
    fn sustained_evidence_still_moves_the_axis() {
        let warm = "love thanks grateful lovely glad kind sweet happy wonderful appreciate";
        let p = profile_of(&[warm]);
        assert!(p.register.warmth > 0.9, "got {}", p.register.warmth);
    }

    /// An axis that reads 1.00 for everyone measures nothing.
    #[test]
    fn hedging_does_not_saturate_on_an_ordinary_corpus() {
        let ordinary = "I think this is probably the right call, though I might be wrong. \
                        Worked on the parser again today and it behaved itself.";
        let p = profile_of(&[ordinary]);
        assert!(
            p.register.hedging < 1.0,
            "an ordinary corpus saturated hedging at {}",
            p.register.hedging
        );
        assert!(p.register.hedging > 0.0, "but hedging is present");
    }
}
