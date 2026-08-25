//! Synthetic corpora.
//!
//! Fixtures are **generated, never real**. Committing real personal data — even
//! your own, even redacted — is the one thing this project cannot walk back
//! (CLAUDE.md §4.14).
//!
//! # Why ground truth is the point
//!
//! A generator that produced plausible-looking notes would let a test assert
//! that the pipeline produced *something*. That is nearly worthless: the
//! interesting failures are the ones where it produces something confident and
//! wrong.
//!
//! So the generator plants a known shape — three people at known frequencies, a
//! Tuesday running habit, a thread that opens on day 3 and closes on day 9 — and
//! hands back [`GroundTruth`] alongside the memories. A test can then ask
//! whether distillation *found* what was put there, which is the question M2's
//! fidelity run actually needs answered.
//!
//! # Deterministic
//!
//! Same clock, same seed, same corpus, byte for byte. A fixture that varied
//! between runs would make every snapshot below it flaky.

use chrono::{Datelike as _, NaiveDate};
use ghostr_core::hash::{Tag, tagged_hash};
use ghostr_core::ids::{MemoryId, SourceId};
use ghostr_core::memory::{Memory, MemoryBody, MemoryKind, Provenance};
use ghostr_core::sensitivity::Sensitivity;
use ghostr_core::time::{Clock, Rng, Timestamp};

/// People the generator plants, with how often each appears.
///
/// Deliberately uneven: a corpus where everyone appears equally often gives a
/// persona model nothing to rank, and ranking is most of what it does.
const CAST: &[(&str, u32)] = &[("Nan", 3), ("Somchai", 7), ("Priya", 14)];

/// Stances the generated notes support, as topic and position.
const STANCES: &[(&str, &str, &str)] = &[
    (
        "remote work",
        "prefers it",
        "Another day at home. I get more done here than in any office.",
    ),
    (
        "early mornings",
        "dislikes them",
        "Dragged myself up at six again. I am not built for this hour.",
    ),
    (
        "long-form writing",
        "values it",
        "Spent the evening on the essay. Slow, but it is the work I care about.",
    ),
];

/// Routines, as a marker and its cadence in days.
const ROUTINES: &[(&str, u32)] = &[("running", 7), ("groceries", 3)];

/// Generates a synthetic corpus with a known shape.
///
/// "Known shape" is what makes assertions possible: a generator that produces a
/// user with three close friends and a Tuesday running habit lets a test check
/// that the persona model *found* them.
#[derive(Debug, Clone)]
pub struct CorpusGenerator {
    days: u32,
    memories_per_day: (u32, u32),
    start: NaiveDate,
    empty_days: Vec<u32>,
    timezone_change: Option<(u32, chrono_tz::Tz)>,
    thread: Option<(String, u32, Option<u32>)>,
}

impl CorpusGenerator {
    /// A generator for a run of days.
    #[must_use]
    pub fn new(days: u32) -> Self {
        Self {
            days,
            memories_per_day: (3, 12),
            start: NaiveDate::from_ymd_opt(2026, 1, 5).unwrap_or_default(),
            empty_days: Vec::new(),
            timezone_change: None,
            // A loop that opens early and closes late, because "did the thread
            // survive six intervening seals?" is the question threads exist to
            // answer.
            thread: Some(("renew the lease".to_owned(), 3, Some(9))),
        }
    }

    /// Starts the run on a given date.
    #[must_use]
    pub const fn starting(mut self, date: NaiveDate) -> Self {
        self.start = date;
        self
    }

    /// Includes days with no memories at all.
    ///
    /// Empty windows still seal and still advance `seq`, and that path is easy
    /// to leave untested until a user takes a weekend off (SPEC §3.4).
    #[must_use]
    pub fn with_empty_days(mut self, count: u32) -> Self {
        // Spread through the run rather than bunched at the end, so a pipeline
        // that mishandles an empty day between two full ones is caught.
        self.empty_days = (0..count)
            .map(|i| (i + 1) * self.days.max(1) / (count + 1))
            .collect();
        self
    }

    /// Includes a timezone change partway through.
    ///
    /// Exercises the cutoff logic against the case it is most likely to get
    /// wrong (SPEC Q11).
    #[must_use]
    pub const fn with_timezone_change(mut self, on_day: u32, to: chrono_tz::Tz) -> Self {
        self.timezone_change = Some((on_day, to));
        self
    }

    /// Replaces the planted thread, or removes it.
    #[must_use]
    pub fn with_thread(mut self, thread: Option<(String, u32, Option<u32>)>) -> Self {
        self.thread = thread;
        self
    }

    /// Generates the corpus.
    #[must_use]
    pub fn generate(&self, clock: &dyn Clock, rng: &dyn Rng) -> SyntheticCorpus {
        let source = SourceId::new(1, [0u8; 10]);
        let mut memories = Vec::new();
        let mut entity_counts: std::collections::BTreeMap<String, u32> =
            std::collections::BTreeMap::new();

        for day in 0..self.days {
            if self.empty_days.contains(&day) {
                continue;
            }
            let date = self.start + chrono::Duration::days(i64::from(day));
            let tz = self.tz_on(day);

            for (index, text) in self.notes_for(day, date).into_iter().enumerate() {
                for (name, _) in CAST {
                    if text.contains(&format!("@{name}")) {
                        *entity_counts.entry((*name).to_owned()).or_default() += 1;
                    }
                }
                memories.push(build(
                    &text,
                    date,
                    tz,
                    u32::try_from(index).unwrap_or(0),
                    source,
                    clock,
                    rng,
                ));
            }
        }

        SyntheticCorpus {
            ground_truth: GroundTruth {
                entities: entity_counts.into_iter().collect(),
                stances: STANCES
                    .iter()
                    .map(|(topic, position, _)| ((*topic).to_owned(), (*position).to_owned()))
                    .collect(),
                routines: ROUTINES
                    .iter()
                    .map(|(name, cadence)| ((*name).to_owned(), *cadence))
                    .collect(),
                threads: self.thread.clone().into_iter().collect(),
                empty_days: self.empty_days.clone(),
                days: self.days,
            },
            memories,
        }
    }

    /// The zone in effect on a given day of the run.
    fn tz_on(&self, day: u32) -> chrono_tz::Tz {
        match self.timezone_change {
            Some((on_day, to)) if day >= on_day => to,
            _ => chrono_tz::Tz::UTC,
        }
    }

    /// The notes for one day.
    ///
    /// Content is a function of the day index, not of the RNG: a corpus whose
    /// *shape* varied with the seed could not carry ground truth. Randomness is
    /// confined to salts and identifiers, which is exactly where it belongs.
    fn notes_for(&self, day: u32, date: NaiveDate) -> Vec<String> {
        let mut out = vec![format!(
            "Day {} of the run. {}",
            day + 1,
            if date.weekday() == chrono::Weekday::Mon {
                "Back to it after the weekend."
            } else {
                "Ordinary enough."
            }
        )];

        // People, each on their own cadence, so frequencies are known.
        for (name, cadence) in CAST {
            if day.is_multiple_of(*cadence) {
                out.push(format!("Coffee with @{name}. Good to catch up."));
            }
        }

        // Stances, repeated often enough to be distillable from evidence
        // rather than from a single mention.
        if let Some((_, _, text)) = STANCES.get(day as usize % STANCES.len()) {
            out.push((*text).to_owned());
        }

        // Routines.
        for (routine, cadence) in ROUTINES {
            if day.is_multiple_of(*cadence) {
                out.push(format!("Did the {routine} again. #routine"));
            }
        }

        // The planted thread, opened and closed on known days.
        if let Some((title, opens, closes)) = &self.thread {
            if day == *opens {
                out.push(format!("- [ ] {title}"));
            }
            if Some(day) == *closes {
                out.push(format!("- [x] {title}"));
            }
        }

        let (min, max) = self.memories_per_day;
        out.truncate(max.max(min) as usize);
        out
    }
}

/// Builds one memory at a stated local time.
fn build(
    text: &str,
    date: NaiveDate,
    tz: chrono_tz::Tz,
    index: u32,
    source: SourceId,
    clock: &dyn Clock,
    rng: &dyn Rng,
) -> Memory {
    use chrono::{NaiveTime, TimeZone as _};

    // Spread through the working day, and never within an hour of a cutoff:
    // a fixture that straddles a boundary tests the fixture, not the pipeline.
    let hour = 9 + (index % 10);
    let local = date.and_time(NaiveTime::from_hms_opt(hour, 0, 0).unwrap_or_default());
    let occurred = tz.from_local_datetime(&local).earliest().map_or_else(
        || Timestamp::new(0, 0),
        |dt| {
            use chrono::Offset as _;
            Timestamp::new(dt.timestamp_millis(), dt.offset().fix().local_minus_utc())
        },
    );

    let mut random = [0u8; 10];
    rng.fill(&mut random);
    let mut salt = [0u8; 32];
    rng.fill(&mut salt);

    Memory {
        id: MemoryId::new(occurred.utc_millis().unsigned_abs(), random),
        source_id: source,
        occurred_at: Some(occurred),
        ingested_at: clock.now(),
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
            external_id: Some(format!("{date}-{index}")),
            url: None,
            raw_hash: tagged_hash(Tag::MemoryLeaf, text.as_bytes()),
        },
        salt,
        supersedes: None,
        embedding: None,
    }
}

/// A generated corpus and the ground truth behind it.
#[derive(Debug, Clone, PartialEq)]
pub struct SyntheticCorpus {
    /// The memories.
    pub memories: Vec<Memory>,
    /// What the generator planted, for assertions.
    ///
    /// The reason this is worth building: a test can check that distillation
    /// recovered the stances and relationships that were deliberately put in,
    /// rather than only that it produced *something*.
    pub ground_truth: GroundTruth,
}

impl SyntheticCorpus {
    /// The memories whose effective time falls on a given day of the run.
    #[must_use]
    pub fn memories_on(&self, day: u32, start: NaiveDate) -> Vec<&Memory> {
        let date = start + chrono::Duration::days(i64::from(day));
        self.memories
            .iter()
            .filter(|m| {
                m.occurred_at
                    .is_some_and(|t| t.to_utc().date_naive() == date)
            })
            .collect()
    }
}

/// What a generator planted.
#[derive(Debug, Clone, PartialEq)]
pub struct GroundTruth {
    /// Entity names and how often each appears.
    pub entities: Vec<(String, u32)>,
    /// Topic and position pairs the corpus supports.
    pub stances: Vec<(String, String)>,
    /// Routines, as pattern and cadence in days.
    pub routines: Vec<(String, u32)>,
    /// Threads, as title, opening day, and closing day if it closes.
    pub threads: Vec<(String, u32, Option<u32>)>,
    /// Days of the run with no memories at all.
    pub empty_days: Vec<u32>,
    /// How many days the run covers, empty ones included.
    pub days: u32,
}

#[cfg(test)]
mod tests {
    use crate::time::{FixedClock, SeededRng};

    use super::*;

    fn generate(generator: &CorpusGenerator) -> SyntheticCorpus {
        let clock = FixedClock::at(Timestamp::new(1_767_000_000_000, 0), chrono_tz::Tz::UTC);
        generator.generate(&clock, &SeededRng::from_seed(42))
    }

    /// A fixture that varied between runs would make every snapshot below it
    /// flaky.
    #[test]
    fn the_same_seed_produces_the_same_corpus() {
        let generator = CorpusGenerator::new(30);
        let a = generate(&generator);
        let b = generate(&generator);
        assert_eq!(a.memories.len(), b.memories.len());
        for (x, y) in a.memories.iter().zip(b.memories.iter()) {
            assert_eq!(x.id, y.id);
            assert_eq!(x.salt, y.salt);
            assert_eq!(x.body.text, y.body.text);
            assert_eq!(x.occurred_at, y.occurred_at);
        }
        assert_eq!(a.ground_truth, b.ground_truth);
    }

    /// The whole reason ground truth exists: a test can ask whether the
    /// pipeline *found* what was planted, not merely that it produced
    /// something.
    #[test]
    fn planted_people_appear_at_the_frequencies_the_ground_truth_claims() {
        let corpus = generate(&CorpusGenerator::new(30));
        for (name, claimed) in &corpus.ground_truth.entities {
            let actual = corpus
                .memories
                .iter()
                .filter(|m| m.body.text.contains(&format!("@{name}")))
                .count();
            assert_eq!(
                usize::try_from(*claimed).unwrap_or(0),
                actual,
                "{name} was claimed {claimed} times but appears {actual}"
            );
        }
    }

    /// Uneven on purpose: a corpus where everyone appears equally often gives a
    /// persona model nothing to rank.
    #[test]
    fn the_cast_appears_at_different_frequencies() {
        let corpus = generate(&CorpusGenerator::new(30));
        let counts: Vec<u32> = corpus
            .ground_truth
            .entities
            .iter()
            .map(|(_, n)| *n)
            .collect();
        assert!(counts.len() >= 3);
        let first = counts[0];
        assert!(
            counts.iter().any(|c| *c != first),
            "every entity appears the same number of times"
        );
    }

    /// SPEC §3.4. Empty windows still seal and still advance `seq`, and that
    /// path stays untested until a user takes a weekend off.
    #[test]
    fn empty_days_are_genuinely_empty_and_are_declared() {
        let corpus = generate(&CorpusGenerator::new(30).with_empty_days(3));
        assert_eq!(corpus.ground_truth.empty_days.len(), 3);
        for day in &corpus.ground_truth.empty_days {
            assert!(
                corpus
                    .memories_on(*day, NaiveDate::from_ymd_opt(2026, 1, 5).unwrap())
                    .is_empty(),
                "day {day} was declared empty but has memories"
            );
        }
    }

    /// Bunching them at the end would miss a pipeline that mishandles an empty
    /// day *between* two full ones.
    #[test]
    fn empty_days_are_spread_through_the_run() {
        let corpus = generate(&CorpusGenerator::new(30).with_empty_days(3));
        let days = &corpus.ground_truth.empty_days;
        assert!(days.iter().any(|d| *d < 15), "none in the first half");
        assert!(days.iter().any(|d| *d >= 15), "none in the second half");
    }

    /// SPEC Q11. The case cutoff logic is most likely to get wrong.
    #[test]
    fn a_timezone_change_shows_up_in_the_recorded_offsets() {
        let corpus = generate(
            &CorpusGenerator::new(20).with_timezone_change(10, chrono_tz::Tz::Asia__Bangkok),
        );
        let offsets: std::collections::BTreeSet<i32> = corpus
            .memories
            .iter()
            .filter_map(|m| m.occurred_at.map(|t| t.offset_seconds()))
            .collect();
        assert!(offsets.contains(&0), "UTC before the change");
        assert!(offsets.contains(&(7 * 3_600)), "+07 after it");
    }

    /// The question threads exist to answer: did it survive the seals between?
    #[test]
    fn the_planted_thread_opens_and_closes_on_the_days_claimed() {
        let corpus = generate(&CorpusGenerator::new(30));
        let (title, opens, closes) = corpus
            .ground_truth
            .threads
            .first()
            .cloned()
            .expect("a planted thread");
        let start = NaiveDate::from_ymd_opt(2026, 1, 5).unwrap();

        assert!(
            corpus
                .memories_on(opens, start)
                .iter()
                .any(|m| m.body.text == format!("- [ ] {title}")),
            "the thread does not open on day {opens}"
        );
        let closes = closes.expect("this thread closes");
        assert!(
            corpus
                .memories_on(closes, start)
                .iter()
                .any(|m| m.body.text == format!("- [x] {title}")),
            "the thread does not close on day {closes}"
        );
        assert!(closes - opens >= 5, "the loop should span several seals");
    }

    /// Stances need repeated evidence: one mention is a remark, not a position.
    #[test]
    fn each_stance_is_supported_more_than_once() {
        let corpus = generate(&CorpusGenerator::new(30));
        assert!(!corpus.ground_truth.stances.is_empty());
        for (topic, _) in &corpus.ground_truth.stances {
            let supporting = STANCES
                .iter()
                .find(|(t, _, _)| t == topic)
                .map(|(_, _, text)| {
                    corpus
                        .memories
                        .iter()
                        .filter(|m| m.body.text == *text)
                        .count()
                })
                .unwrap_or(0);
            assert!(
                supporting > 1,
                "{topic} is supported only {supporting} time(s)"
            );
        }
    }

    /// Salts must differ per memory: two identical notes sharing a salt would
    /// hash to the same leaf, which is what salting prevents (SPEC §7.2).
    #[test]
    fn every_memory_gets_its_own_salt() {
        let corpus = generate(&CorpusGenerator::new(30));
        let salts: std::collections::BTreeSet<[u8; 32]> =
            corpus.memories.iter().map(|m| m.salt).collect();
        assert_eq!(salts.len(), corpus.memories.len());
    }

    /// A fixture that straddles a cutoff tests the fixture, not the pipeline.
    #[test]
    fn no_memory_lands_near_a_cutoff_boundary() {
        use chrono::Timelike as _;

        let corpus = generate(&CorpusGenerator::new(30));
        for memory in &corpus.memories {
            let hour = memory.occurred_at.expect("dated").to_local().hour();
            assert!(
                (1..23).contains(&hour),
                "a memory at {hour}:00 local is too close to a cutoff"
            );
        }
    }
}
