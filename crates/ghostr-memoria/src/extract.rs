//! Deterministic extraction from note text.
//!
//! M0 has no model. Everything here is a pure function of the input, which
//! matters for more than testability: extraction output is committed into the
//! day's Merkle tree, so two runs over the same window must produce the same
//! bytes or the same data would yield two different roots.
//!
//! # What is extracted, and how
//!
//! | Signal | Marker |
//! | --- | --- |
//! | People | `@name` |
//! | Topics | `#tag` |
//! | Linked things | `[[wiki link]]` |
//! | Open threads | `- [ ]`, `TODO` |
//! | Closed loops | `- [x]`, `DONE` |
//! | Mood | a fixed word lexicon |
//!
//! Explicit markers rather than inference. A heuristic that guesses at people
//! from capitalisation gets "Monday" and "Bangkok" wrong constantly, and a
//! memory system that invents relationships is worse than one that misses them.
//!
//! # When the LLM arrives
//!
//! The `llm` feature adds the schema-constrained path (THREAT_MODEL §T7): no
//! tools, no network, structured output only, corpus text as data. The
//! deterministic extractor stays as the fallback, so a model outage degrades
//! the recap rather than stopping the day from sealing.

use std::collections::BTreeMap;

use ghostr_core::footage::{MoodBasis, MoodReading};
use serde::{Deserialize, Serialize};

/// Everything the deterministic extractor found in one note.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Extraction {
    /// `@name` mentions, deduplicated, in first-appearance order.
    pub people: Vec<String>,
    /// `#tag` topics.
    pub topics: Vec<String>,
    /// `[[wiki links]]`.
    pub links: Vec<String>,
    /// Unfinished items.
    pub open_threads: Vec<String>,
    /// Items marked done.
    pub closed_loops: Vec<String>,
    /// Questions the note left hanging.
    pub questions: Vec<String>,
    /// This note's contribution to the day's mood.
    pub mood: MoodContribution,
}

/// A note's contribution to the day's mood.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct MoodContribution {
    /// Pleasantness in `-1.0..=1.0`.
    pub valence: f32,
    /// Activation in `0.0..=1.0`.
    pub arousal: f32,
    /// How many lexicon words matched. Zero means no signal, not neutral.
    pub matches: u32,
}

impl Default for MoodContribution {
    fn default() -> Self {
        Self {
            valence: 0.0,
            arousal: 0.0,
            matches: 0,
        }
    }
}

/// Words that move valence. Small, fixed, and inspectable on purpose.
///
/// A short list a reader can audit beats a large one they cannot. When the mood
/// reading is wrong, the user should be able to see exactly why.
const POSITIVE: &[&str] = &[
    "good",
    "great",
    "happy",
    "glad",
    "love",
    "loved",
    "excited",
    "calm",
    "proud",
    "relieved",
    "fixed",
    "shipped",
    "finished",
    "solved",
    "wonderful",
    "lovely",
    "grateful",
];

/// Words that move valence negatively.
const NEGATIVE: &[&str] = &[
    "bad",
    "sad",
    "angry",
    "tired",
    "exhausted",
    "anxious",
    "stuck",
    "broken",
    "failed",
    "frustrated",
    "worried",
    "stressed",
    "awful",
    "annoyed",
    "lonely",
];

/// Words that raise arousal regardless of direction.
const HIGH_AROUSAL: &[&str] = &[
    "excited", "angry", "anxious", "stressed", "frantic", "urgent", "panic", "thrilled",
];

/// Runs the deterministic extractor over one note.
#[must_use]
pub fn extract(text: &str) -> Extraction {
    let mut out = Extraction::default();

    for line in text.lines() {
        let trimmed = line.trim();
        let lower = trimmed.to_lowercase();

        // Checked list items and TODO/DONE markers become threads. Order matters:
        // `- [x]` must be tested before `- [`, or a done item reads as open.
        if let Some(rest) = trimmed
            .strip_prefix("- [x]")
            .or_else(|| trimmed.strip_prefix("- [X]"))
        {
            push_unique(&mut out.closed_loops, rest.trim());
        } else if let Some(rest) = trimmed.strip_prefix("- [ ]") {
            push_unique(&mut out.open_threads, rest.trim());
        } else if lower.contains("todo") {
            push_unique(&mut out.open_threads, strip_marker(trimmed, "todo"));
        } else if lower.contains("done:") {
            push_unique(&mut out.closed_loops, strip_marker(trimmed, "done:"));
        }

        if trimmed.ends_with('?') && trimmed.split_whitespace().count() > 2 {
            push_unique(&mut out.questions, trimmed);
        }
    }

    for token in tokens(text) {
        if let Some(name) = token.strip_prefix('@') {
            let cleaned = name.trim_end_matches(|c: char| !c.is_alphanumeric() && c != '_');
            if !cleaned.is_empty() {
                push_unique(&mut out.people, cleaned);
            }
        } else if let Some(tag) = token.strip_prefix('#') {
            let cleaned =
                tag.trim_end_matches(|c: char| !c.is_alphanumeric() && c != '_' && c != '-');
            if !cleaned.is_empty() {
                push_unique(&mut out.topics, cleaned);
            }
        }
    }

    out.links = wiki_links(text);
    out.mood = mood_of(text);
    out
}

/// Combines per-note contributions into one reading for the day.
///
/// Weighted by how many lexicon words each note matched, so a long emotive note
/// outweighs a one-line log entry. A day with no matches at all reports zero
/// confidence rather than a confident neutral — "we could not tell" and "it was
/// an average day" are different claims.
#[must_use]
pub fn combine_mood(contributions: &[MoodContribution]) -> MoodReading {
    let total: u32 = contributions.iter().map(|c| c.matches).sum();
    if total == 0 {
        return MoodReading {
            valence: 0.0,
            arousal: 0.0,
            labels: Vec::new(),
            confidence: 0.0,
            basis: MoodBasis::Inferred,
        };
    }
    let weight = f32::from(u16::try_from(total).unwrap_or(u16::MAX));
    let valence = contributions
        .iter()
        .map(|c| c.valence * f32::from(u16::try_from(c.matches).unwrap_or(0)))
        .sum::<f32>()
        / weight;
    let arousal = contributions
        .iter()
        .map(|c| c.arousal * f32::from(u16::try_from(c.matches).unwrap_or(0)))
        .sum::<f32>()
        / weight;

    let mut labels = Vec::new();
    if valence > 0.25 {
        labels.push("positive".to_owned());
    } else if valence < -0.25 {
        labels.push("negative".to_owned());
    } else {
        labels.push("mixed".to_owned());
    }
    if arousal > 0.5 {
        labels.push("high-energy".to_owned());
    }

    MoodReading {
        valence: valence.clamp(-1.0, 1.0),
        arousal: arousal.clamp(0.0, 1.0),
        labels,
        // Confidence grows with evidence and saturates: ten matching words is
        // about as sure as a word list can make anyone.
        confidence: (weight / 10.0).min(1.0),
        basis: MoodBasis::Inferred,
    }
}

fn mood_of(text: &str) -> MoodContribution {
    let mut positive = 0u32;
    let mut negative = 0u32;
    let mut aroused = 0u32;

    for token in tokens(text) {
        let word = token
            .trim_matches(|c: char| !c.is_alphanumeric())
            .to_lowercase();
        if word.is_empty() {
            continue;
        }
        if POSITIVE.contains(&word.as_str()) {
            positive += 1;
        }
        if NEGATIVE.contains(&word.as_str()) {
            negative += 1;
        }
        if HIGH_AROUSAL.contains(&word.as_str()) {
            aroused += 1;
        }
    }

    let matches = positive + negative;
    if matches == 0 {
        return MoodContribution::default();
    }
    let valence = (f64::from(positive) - f64::from(negative)) / f64::from(matches);
    MoodContribution {
        valence: valence as f32,
        arousal: (f64::from(aroused) / f64::from(matches)).min(1.0) as f32,
        matches,
    }
}

fn tokens(text: &str) -> impl Iterator<Item = &str> {
    text.split(|c: char| c.is_whitespace())
}

fn wiki_links(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find("[[") {
        let after = &rest[start + 2..];
        let Some(end) = after.find("]]") else { break };
        push_unique(&mut out, after[..end].trim());
        rest = &after[end + 2..];
    }
    out
}

fn strip_marker<'a>(line: &'a str, marker: &str) -> &'a str {
    let lower = line.to_lowercase();
    lower.find(marker).map_or(line, |at| {
        line[at + marker.len()..].trim_start_matches([':', ' '])
    })
}

fn push_unique(out: &mut Vec<String>, value: &str) {
    let value = value.trim();
    if value.is_empty() {
        return;
    }
    if !out.iter().any(|v| v == value) {
        out.push(value.to_owned());
    }
}

/// Counts how often each person appears across a day's extractions.
///
/// A `BTreeMap` so iteration order is deterministic: this feeds the footage,
/// which is hashed.
#[must_use]
pub fn people_frequency(extractions: &[Extraction]) -> BTreeMap<String, u32> {
    let mut counts = BTreeMap::new();
    for e in extractions {
        for person in &e.people {
            *counts.entry(person.clone()).or_insert(0) += 1;
        }
    }
    counts
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_people_topics_and_links() {
        let e = extract("saw @nan and @somchai about #moving, see [[the lease]]");
        assert_eq!(e.people, vec!["nan", "somchai"]);
        assert_eq!(e.topics, vec!["moving"]);
        assert_eq!(e.links, vec!["the lease"]);
    }

    #[test]
    fn a_done_item_is_not_read_as_open() {
        // `- [x]` must be matched before `- [`, or every completed task would
        // reopen itself every day.
        let e = extract("- [x] pay rent\n- [ ] call the bank");
        assert_eq!(e.closed_loops, vec!["pay rent"]);
        assert_eq!(e.open_threads, vec!["call the bank"]);
    }

    #[test]
    fn todo_and_done_markers_are_picked_up() {
        let e = extract("TODO: renew the passport\nDONE: booked the flight");
        assert_eq!(e.open_threads, vec!["renew the passport"]);
        assert_eq!(e.closed_loops, vec!["booked the flight"]);
    }

    #[test]
    fn questions_need_more_than_two_words() {
        // "why?" is punctuation, not an open question worth surfacing.
        let e = extract("why?\nshould I take the later train?");
        assert_eq!(e.questions, vec!["should I take the later train?"]);
    }

    #[test]
    fn duplicates_are_collapsed_in_first_appearance_order() {
        let e = extract("@nan @somchai @nan");
        assert_eq!(e.people, vec!["nan", "somchai"]);
    }

    #[test]
    fn punctuation_after_a_mention_is_trimmed() {
        let e = extract("thanks @nan, and @somchai!");
        assert_eq!(e.people, vec!["nan", "somchai"]);
    }

    #[test]
    fn a_day_with_no_mood_words_reports_zero_confidence() {
        // "we could not tell" and "it was an average day" are different claims,
        // and the reading must not conflate them.
        let reading = combine_mood(&[extract("commit 3f2a1b. rebased onto main.").mood]);
        assert_eq!(reading.confidence, 0.0);
        assert!(reading.labels.is_empty());
    }

    #[test]
    fn mood_direction_follows_the_lexicon() {
        let good = combine_mood(&[extract("fixed it, shipped it, feeling great").mood]);
        let bad = combine_mood(&[extract("stuck, frustrated, exhausted").mood]);
        assert!(good.valence > 0.0, "got {}", good.valence);
        assert!(bad.valence < 0.0, "got {}", bad.valence);
        assert!(good.confidence > 0.0 && bad.confidence > 0.0);
    }

    #[test]
    fn mood_is_weighted_by_evidence() {
        // One emotive note should outweigh one passing word.
        let strong = extract("great great great great wonderful lovely proud glad").mood;
        let weak = extract("tired").mood;
        let combined = combine_mood(&[strong, weak]);
        assert!(combined.valence > 0.5, "got {}", combined.valence);
    }

    #[test]
    fn extraction_is_deterministic() {
        let text = "@nan #moving TODO: pack\n- [x] rent\nfeeling glad";
        assert_eq!(extract(text), extract(text));
    }

    #[test]
    fn people_frequency_is_ordered() {
        let counts = people_frequency(&[extract("@zed @amy"), extract("@amy")]);
        let keys: Vec<_> = counts.keys().cloned().collect();
        assert_eq!(keys, vec!["amy".to_owned(), "zed".to_owned()]);
        assert_eq!(counts["amy"], 2);
    }
}
