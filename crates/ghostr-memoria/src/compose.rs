//! Assembling extractions into a draft footage.
//!
//! Composition is where the hallucination guard lives: every claim that reaches
//! a draft must carry at least one `memory_id`, and anything without evidence is
//! dropped here rather than caught later. Validation is the backstop, not the
//! filter (SPEC §6).

use ghostr_core::footage::{Highlight, MoodReading, OpenQuestion, PersonBeat, Thread};
use ghostr_core::ids::MemoryId;
use ghostr_core::memory::Memory;

use crate::extract::{Extraction, combine_mood};
use crate::summarize::Summarizer;

/// How long a highlight summary may be.
const HIGHLIGHT_CHARS: usize = 160;

/// One note plus what was extracted from it.
#[derive(Debug, Clone)]
pub struct NoteExtraction<'a> {
    /// The memory this came from.
    pub memory: &'a Memory,
    /// What the deterministic extractor found.
    pub extraction: Extraction,
}

/// Builds highlights, ranked by salience and capped at `limit`.
///
/// Every highlight cites exactly the memory it came from. There is no path here
/// that produces a summary without evidence, which is what keeps a hallucinated
/// claim out of the chain.
#[must_use]
pub fn highlights(
    notes: &[NoteExtraction<'_>],
    summarizer: &dyn Summarizer,
    limit: usize,
) -> Vec<Highlight> {
    let mut out: Vec<Highlight> = notes
        .iter()
        .filter_map(|note| {
            let summary = summarizer.summarize(&note.memory.body.text, HIGHLIGHT_CHARS);
            if summary.is_empty() {
                // An empty note produces no highlight rather than an empty one.
                return None;
            }
            Some(Highlight {
                summary,
                memory_ids: vec![note.memory.id],
                salience: note.memory.salience,
            })
        })
        .collect();

    // Ties break on memory id so the ordering is total and reproducible: the
    // highlight list is hashed into the day's root.
    out.sort_by(|a, b| {
        b.salience
            .partial_cmp(&a.salience)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.memory_ids.cmp(&b.memory_ids))
    });
    out.truncate(limit);
    out
}

/// Rolls up per-note mood into one reading for the day.
#[must_use]
pub fn mood(notes: &[NoteExtraction<'_>]) -> MoodReading {
    let contributions: Vec<_> = notes.iter().map(|n| n.extraction.mood).collect();
    combine_mood(&contributions)
}

/// Builds person beats from `@mentions`.
///
/// Only people the day's notes actually named. An entity with no supporting
/// memory is dropped, which is the same evidence rule highlights follow.
#[must_use]
pub fn people(
    notes: &[NoteExtraction<'_>],
    resolve: &dyn Fn(&str) -> ghostr_core::ids::EntityId,
) -> Vec<PersonBeat> {
    use std::collections::BTreeMap;

    use ghostr_core::footage::InteractionKind;

    let mut by_name: BTreeMap<&str, Vec<MemoryId>> = BTreeMap::new();
    for note in notes {
        for person in &note.extraction.people {
            by_name
                .entry(person.as_str())
                .or_default()
                .push(note.memory.id);
        }
    }
    by_name
        .into_iter()
        .map(|(name, memory_ids)| PersonBeat {
            entity: resolve(name),
            // M0 has no model, so it does not guess at the nature of an
            // interaction. `Mentioned` is what the marker actually evidences.
            interaction: InteractionKind::Mentioned,
            valence: None,
            memory_ids,
        })
        .collect()
}

/// Collects unresolved questions, each tied to the note that raised it.
#[must_use]
pub fn unresolved(notes: &[NoteExtraction<'_>]) -> Vec<OpenQuestion> {
    let mut out = Vec::new();
    for note in notes {
        for question in &note.extraction.questions {
            out.push(OpenQuestion {
                question: question.clone(),
                memory_ids: vec![note.memory.id],
            });
        }
    }
    out
}

/// Diffs today's thread markers against the threads carried forward.
///
/// Matching is by title text in M0, since there is no model to resolve a
/// restatement. That is a real limitation: rewording an open item creates a
/// second thread rather than continuing the first. Recorded here rather than
/// hidden, because it is the first thing an LLM backend should fix.
#[must_use]
pub fn threads(
    previous_open: &[Thread],
    notes: &[NoteExtraction<'_>],
    seq: u64,
    next_id: &dyn Fn() -> ghostr_core::ids::ThreadId,
) -> ThreadUpdate {
    use ghostr_core::footage::ThreadState;

    let mut open: Vec<Thread> = previous_open.to_vec();
    let mut closed = Vec::new();
    let mut opened = Vec::new();

    for note in notes {
        for title in &note.extraction.open_threads {
            if let Some(existing) = open.iter_mut().find(|t| &t.title == title) {
                existing.last_touched_seq = seq;
                existing.memory_ids.push(note.memory.id);
            } else {
                let id = next_id();
                opened.push(id);
                open.push(Thread {
                    id,
                    title: title.clone(),
                    opened_seq: seq,
                    last_touched_seq: seq,
                    state: ThreadState::Open,
                    memory_ids: vec![note.memory.id],
                });
            }
        }
    }

    for note in notes {
        for title in &note.extraction.closed_loops {
            if let Some(pos) = open.iter().position(|t| &t.title == title) {
                let mut thread = open.remove(pos);
                thread.state = ThreadState::Closed;
                thread.last_touched_seq = seq;
                thread.memory_ids.push(note.memory.id);
                closed.push(thread.id);
            }
            // A `- [x]` for something never opened is not an error. Users tick
            // off things they never wrote down, and inventing a thread just to
            // close it would be noise.
        }
    }

    // Deterministic order: the thread list is hashed into the day's root.
    open.sort_by(|a, b| {
        a.opened_seq
            .cmp(&b.opened_seq)
            .then_with(|| a.title.cmp(&b.title))
    });
    closed.sort();
    opened.sort();

    ThreadUpdate {
        open,
        closed,
        opened,
    }
}

/// How threads changed over one day.
#[derive(Debug, Clone, PartialEq)]
pub struct ThreadUpdate {
    /// Threads open at the cutoff, new ones included.
    pub open: Vec<Thread>,
    /// Threads that closed today.
    pub closed: Vec<ghostr_core::ids::ThreadId>,
    /// Every thread this pass opened, including ones it then closed.
    ///
    /// Ticking a task off the day you wrote it down is the commonest thing
    /// anyone does with a checkbox, and such a thread is in neither `open` (it
    /// closed) nor the previous day's carry (it did not exist yet). Without
    /// this the validator sees a loop closing that was never opened, and
    /// refuses to seal the day at all.
    pub opened: Vec<ghostr_core::ids::ThreadId>,
}

#[cfg(test)]
mod tests {
    use ghostr_core::ids::{EntityId, ThreadId};

    use super::*;
    use crate::extract::extract;
    use crate::summarize::NaiveSummarizer;

    fn memory(n: u8, text: &str, salience: f32) -> Memory {
        use ghostr_core::memory::{MemoryBody, MemoryKind, Provenance};
        use ghostr_core::sensitivity::Sensitivity;
        use ghostr_core::time::Timestamp;

        let source = ghostr_core::ids::SourceId::new(1, [0u8; 10]);
        Memory {
            id: MemoryId::new(1_700_000_000_000 + u64::from(n), [n; 10]),
            source_id: source,
            occurred_at: Some(Timestamp::new(1_700_000_000_000, 0)),
            ingested_at: Timestamp::new(1_700_000_000_000, 0),
            kind: MemoryKind::Utterance,
            body: MemoryBody {
                text: text.to_owned(),
                structured: None,
                redactions: Vec::new(),
            },
            entities: Vec::new(),
            salience,
            sensitivity: Sensitivity::Private,
            provenance: Provenance {
                source_id: source,
                external_id: None,
                url: None,
                raw_hash: ghostr_core::hash::tagged_hash(ghostr_core::hash::Tag::MemoryLeaf, &[n]),
            },
            salt: [n; 32],
            supersedes: None,
            embedding: None,
        }
    }

    fn notes<'a>(memories: &'a [Memory]) -> Vec<NoteExtraction<'a>> {
        memories
            .iter()
            .map(|m| NoteExtraction {
                memory: m,
                extraction: extract(&m.body.text),
            })
            .collect()
    }

    #[test]
    fn highlights_are_ranked_and_always_cite_evidence() {
        let mems = vec![
            memory(1, "Quiet morning.", 0.2),
            memory(2, "Shipped the parser after three days stuck on it.", 0.9),
        ];
        let hs = highlights(&notes(&mems), &NaiveSummarizer, 10);
        assert_eq!(hs.len(), 2);
        assert!(hs[0].summary.contains("Shipped the parser"));
        for h in &hs {
            assert!(
                !h.memory_ids.is_empty(),
                "a highlight without evidence is a hallucination"
            );
        }
    }

    #[test]
    fn an_empty_note_produces_no_highlight() {
        let mems = vec![memory(1, "   \n\n", 0.5)];
        assert!(highlights(&notes(&mems), &NaiveSummarizer, 10).is_empty());
    }

    #[test]
    fn highlight_order_is_total_so_the_root_is_reproducible() {
        // Equal salience must still order deterministically, or two runs would
        // hash to different roots.
        let mems = vec![memory(1, "Note one.", 0.5), memory(2, "Note two.", 0.5)];
        let a = highlights(&notes(&mems), &NaiveSummarizer, 10);
        let b = highlights(&notes(&mems), &NaiveSummarizer, 10);
        assert_eq!(a, b);
    }

    #[test]
    fn a_thread_opened_and_later_closed_becomes_a_closed_loop() {
        let day1 = vec![memory(1, "- [ ] fix the tz bug", 0.5)];
        let update1 = threads(&[], &notes(&day1), 1, &|| ThreadId::new(1, [1u8; 10]));
        assert_eq!(update1.open.len(), 1);
        assert!(update1.closed.is_empty());

        let day2 = vec![memory(2, "- [x] fix the tz bug", 0.5)];
        let update2 = threads(&update1.open, &notes(&day2), 2, &|| {
            ThreadId::new(2, [2u8; 10])
        });
        assert!(update2.open.is_empty());
        assert_eq!(update2.closed.len(), 1);
    }

    #[test]
    fn closing_something_never_opened_is_not_an_error() {
        let day = vec![memory(1, "- [x] something I never wrote down", 0.5)];
        let update = threads(&[], &notes(&day), 1, &|| ThreadId::new(1, [1u8; 10]));
        assert!(update.open.is_empty());
        assert!(update.closed.is_empty());
    }

    #[test]
    fn people_are_only_those_the_notes_named() {
        let mems = vec![
            memory(1, "coffee with @nan", 0.5),
            memory(2, "no one today", 0.5),
        ];
        let beats = people(&notes(&mems), &|_| EntityId::new(1, [1u8; 10]));
        assert_eq!(beats.len(), 1);
        assert_eq!(beats[0].memory_ids, vec![mems[0].id]);
    }

    /// Ticking a task off the day you wrote it down is the commonest thing
    /// anyone does with a checkbox — and until this was fixed it made the whole
    /// day unsealable, because the loop closing had never been carried in.
    #[test]
    fn a_thread_opened_and_closed_the_same_day_is_reported_as_opened() {
        let memory = memory(1, "- [ ] groceries\n- [x] groceries", 0.5);
        let notes = vec![NoteExtraction {
            memory: &memory,
            extraction: extract(&memory.body.text),
        }];
        let next = std::cell::Cell::new(0u64);
        let update = threads(&[], &notes, 1, &|| {
            next.set(next.get() + 1);
            ThreadId::new(next.get(), [1u8; 10])
        });

        assert_eq!(update.closed.len(), 1, "it closed");
        assert!(
            update.open.is_empty(),
            "and is no longer open, which is why it needs reporting separately"
        );
        assert_eq!(
            update.opened, update.closed,
            "the day must still record having opened it"
        );
    }

    /// A `- [x]` for something never written down is not an error — people tick
    /// off things they never listed — so it must not be reported as opened.
    #[test]
    fn closing_something_never_opened_reports_no_open() {
        let memory = memory(1, "- [x] something I never wrote down", 0.5);
        let notes = vec![NoteExtraction {
            memory: &memory,
            extraction: extract(&memory.body.text),
        }];
        let update = threads(&[], &notes, 1, &|| ThreadId::new(1, [1u8; 10]));

        assert!(update.opened.is_empty());
        assert!(update.closed.is_empty(), "there was nothing to close");
    }
}
