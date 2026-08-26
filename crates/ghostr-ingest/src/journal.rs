//! The journal: entries made inside Ghostr.
//!
//! A journal entry is typed with `ghostr journal add` and goes straight into the
//! encrypted store. There is no journal file: Ghostr never writes a plaintext
//! entry to disk, not even its own (I1). That is why
//! [`SourceKind::Journal`](ghostr_core::source::SourceKind::Journal) carries no
//! location, and why [`JournalAdapter`]'s [`pull`](crate::IngestAdapter::pull)
//! returns an empty batch — the journal is a push source with nothing to poll.
//!
//! # Importing a running journal
//!
//! Most people arrive with a diary already written: one file appended to for
//! years, with a timestamp heading before each entry.
//!
//! ```text
//! ## 2026-08-25 09:14
//! Slept badly. Standup moved to 10.
//!
//! ## 2026-08-25 21:02
//! Dinner with @nan. She's taking the clinic job.
//! ```
//!
//! [`parse`] splits such a file into entries, and `ghostr journal import` stores
//! them. The unit is the entry, not the file: appending one entry to the source
//! file and re-importing produces exactly one new memory, because each entry's
//! `raw_hash` covers only itself. Handing the same file to the markdown adapter
//! would instead re-ingest the whole thing on every append.
//!
//! Importing copies the entries into the vault. The original file stays the
//! user's, wherever they keep it; Ghostr does not manage it and never writes
//! back to it.

use std::path::{Path, PathBuf};

use chrono::{NaiveDate, NaiveDateTime, NaiveTime};
use ghostr_core::hash::{Tag, tagged_hash};
use ghostr_core::ids::{MemoryId, SourceId};
use ghostr_core::memory::{Memory, MemoryBody, MemoryKind, Provenance};
use ghostr_core::sensitivity::{Sensitivity, TrustLevel};
use ghostr_core::source::SourceKindTag;
use ghostr_core::time::{Clock, Rng, Timestamp};

use crate::adapter::TimeBasis;

/// The source-kind tag this adapter registers under.
pub const KIND_TAG: &str = "journal";

/// File extensions treated as journal files when a directory is scanned.
const EXTENSIONS: &[&str] = &["md", "txt", "journal"];

/// One entry, before it becomes a [`Memory`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JournalEntry {
    /// Which file it came from, relative to the scan root.
    pub relative_path: String,
    /// The heading as written, kept verbatim as the entry's external id.
    pub heading: String,
    /// When the entry says it happened, in the user's local wall clock.
    pub at: NaiveDateTime,
    /// The entry body, heading stripped.
    pub text: String,
    /// How `at` was determined.
    pub basis: TimeBasis,
}

/// Reads every entry from a journal file, or from every journal file under a
/// directory.
///
/// Ordering is by path and then by position in the file, so two runs over an
/// unchanged journal produce the same entries in the same order.
///
/// # Errors
///
/// Returns [`Error::Unreachable`](crate::Error::Unreachable) if the path does
/// not exist or cannot be read.
pub fn scan(root: &Path, source: SourceId) -> crate::Result<Vec<JournalEntry>> {
    let mut files: Vec<PathBuf> = if root.is_file() {
        vec![root.to_path_buf()]
    } else if root.is_dir() {
        walkdir::WalkDir::new(root)
            .follow_links(false)
            .into_iter()
            .filter_map(Result::ok)
            .filter(|e| e.file_type().is_file())
            .map(walkdir::DirEntry::into_path)
            .filter(|p| {
                p.extension()
                    .and_then(|e| e.to_str())
                    .is_some_and(|e| EXTENSIONS.iter().any(|k| e.eq_ignore_ascii_case(k)))
            })
            .collect()
    } else {
        return Err(crate::Error::Unreachable { id: source });
    };
    files.sort();

    let mut out = Vec::new();
    for path in files {
        let Ok(raw) = std::fs::read_to_string(&path) else {
            // Not UTF-8. Skipped rather than fatal: one binary file with a .txt
            // extension should not abort the import.
            continue;
        };
        let relative_path = if root.is_file() {
            path.file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default()
        } else {
            path.strip_prefix(root)
                .unwrap_or(&path)
                .to_string_lossy()
                .replace('\\', "/")
        };
        out.extend(parse(&raw, &relative_path));
    }
    Ok(out)
}

/// Splits journal text into entries at its timestamp headings.
///
/// Text before the first heading is dropped: in a journal file that is a title
/// or a preamble, not an entry, and dating it would mean inventing a time.
#[must_use]
pub fn parse(raw: &str, relative_path: &str) -> Vec<JournalEntry> {
    let mut out: Vec<JournalEntry> = Vec::new();
    let mut current: Option<(String, NaiveDateTime, TimeBasis, Vec<&str>)> = None;

    for line in raw.lines() {
        if let Some((at, basis)) = parse_heading(line) {
            if let Some((heading, at, basis, body)) = current.take() {
                push(&mut out, relative_path, heading, at, basis, &body);
            }
            current = Some((line.trim().to_owned(), at, basis, Vec::new()));
        } else if let Some((_, _, _, body)) = current.as_mut() {
            body.push(line);
        }
    }
    if let Some((heading, at, basis, body)) = current {
        push(&mut out, relative_path, heading, at, basis, &body);
    }
    out
}

/// Appends one entry, dropping it if its body is empty.
///
/// A heading with nothing under it is a day the user opened and did not write
/// in. Storing an empty memory for it would put a highlight-less, evidence-less
/// row into the corpus for every such day.
fn push(
    out: &mut Vec<JournalEntry>,
    relative_path: &str,
    heading: String,
    at: NaiveDateTime,
    basis: TimeBasis,
    body: &[&str],
) {
    let text = body.join("\n").trim().to_owned();
    if text.is_empty() {
        return;
    }
    out.push(JournalEntry {
        relative_path: relative_path.to_owned(),
        heading,
        at,
        text,
        basis,
    });
}

/// Recognises a timestamp heading and the precision it carries.
///
/// Accepts `## 2026-08-25 09:14`, `## 2026-08-25T09:14`, `## 2026-08-25`, and
/// the same three in `[...]` brackets. A date with no time lands at local noon
/// and is recorded as [`TimeBasis::ParsedFromContent`] rather than
/// [`TimeBasis::Stated`]: the user stated the day, not the moment, and a footage
/// window built from a guessed hour should not claim otherwise.
fn parse_heading(line: &str) -> Option<(NaiveDateTime, TimeBasis)> {
    let trimmed = line.trim();
    let body = trimmed
        .trim_start_matches('#')
        .trim()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .trim();

    // A date is the first 10 characters or nothing.
    let date: NaiveDate = body.get(..10)?.parse().ok()?;
    let rest = body.get(10..).unwrap_or("").trim_start_matches(['T', ' ']);

    let time = rest
        .get(..5)
        .and_then(|hm| NaiveTime::parse_from_str(hm, "%H:%M").ok());

    match time {
        Some(t) => Some((NaiveDateTime::new(date, t), TimeBasis::Stated)),
        None if rest.trim().is_empty() || rest.starts_with('—') || rest.starts_with('-') => {
            Some((
                NaiveDateTime::new(date, NaiveTime::from_hms_opt(12, 0, 0)?),
                TimeBasis::ParsedFromContent,
            ))
        }
        // A line starting with a date but continuing into prose ("2026-08-25 was
        // a long day") is content, not a heading.
        None => None,
    }
}

/// Converts a parsed entry into a memory.
///
/// `raw_hash` is taken over the file, the heading, and the body, so re-reading
/// an unchanged journal produces the same digest and the store's unique index
/// makes the second run a no-op — while appending an entry produces exactly one
/// new memory.
#[must_use]
pub fn to_memory(
    entry: &JournalEntry,
    source: SourceId,
    clock: &dyn Clock,
    rng: &dyn Rng,
) -> Memory {
    let now = clock.now();
    let raw_hash = tagged_hash(
        Tag::MemoryLeaf,
        format!(
            "{}\u{0}{}\u{0}{}",
            entry.relative_path, entry.heading, entry.text
        )
        .as_bytes(),
    );

    let mut random = [0u8; 10];
    rng.fill(&mut random);
    let mut salt = [0u8; 32];
    rng.fill(&mut salt);

    Memory {
        id: MemoryId::new(now.utc_millis().unsigned_abs(), random),
        source_id: source,
        occurred_at: Some(Timestamp::new(entry.at.and_utc().timestamp_millis(), 0)),
        ingested_at: now,
        kind: MemoryKind::Utterance,
        body: MemoryBody {
            text: entry.text.clone(),
            structured: None,
            redactions: Vec::new(),
        },
        entities: Vec::new(),
        salience: crate::markdown::salience_of(&entry.text),
        sensitivity: Sensitivity::Private,
        provenance: Provenance {
            source_id: source,
            external_id: Some(format!("{}#{}", entry.relative_path, entry.heading)),
            url: None,
            raw_hash,
        },
        salt,
        supersedes: None,
        embedding: None,
    }
}

/// The trust level journal content carries.
///
/// [`TrustLevel::FirstParty`]: the user wrote it. Eligible as a voice exemplar,
/// which is precisely why a feed adapter must never return this
/// (THREAT_MODEL §T7).
#[must_use]
pub const fn default_trust() -> TrustLevel {
    TrustLevel::FirstParty
}

/// The source-kind tag.
#[must_use]
pub const fn kind() -> SourceKindTag {
    SourceKindTag::Journal
}

/// The journal source, as an [`IngestAdapter`](crate::IngestAdapter).
///
/// A push source: entries arrive when the user makes them, so there is nothing
/// to poll and [`pull`](crate::IngestAdapter::pull) returns an empty batch. It is
/// registered all the same, because `ghostr source list` should show the journal
/// alongside everything else rather than leaving the user to wonder where their
/// entries are accounted for.
#[derive(Debug, Default, Clone, Copy)]
pub struct JournalAdapter;

#[async_trait::async_trait]
impl crate::adapter::IngestAdapter for JournalAdapter {
    fn kind(&self) -> SourceKindTag {
        SourceKindTag::Journal
    }

    async fn pull(
        &self,
        source: &ghostr_core::source::Source,
        cursor: ghostr_core::source::SyncCursor,
    ) -> crate::Result<crate::adapter::IngestBatch> {
        if !matches!(source.kind, ghostr_core::source::SourceKind::Journal) {
            return Err(crate::Error::InvalidCursor { id: source.id });
        }
        Ok(crate::adapter::IngestBatch {
            memories: Vec::new(),
            // Unchanged: a pull that advanced a push source's cursor would skip
            // whatever was written between the two.
            cursor,
            has_more: false,
            duplicates_skipped: 0,
            unparseable_skipped: 0,
        })
    }

    fn default_trust(&self) -> TrustLevel {
        default_trust()
    }

    fn default_sensitivity(&self) -> Sensitivity {
        Sensitivity::Private
    }

    fn touches_network(&self) -> bool {
        false
    }

    async fn validate(&self, source: &ghostr_core::source::Source) -> crate::Result<()> {
        if matches!(source.kind, ghostr_core::source::SourceKind::Journal) {
            Ok(())
        } else {
            Err(crate::Error::InvalidCursor { id: source.id })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "\
# My journal

Some preamble that is not an entry.

## 2026-08-25 09:14
Slept badly. Standup moved to 10.

## 2026-08-25 21:02
Dinner with @nan.
She's taking the clinic job.

## 2026-08-26
Quiet day.
";

    #[test]
    fn entries_split_at_their_headings() {
        let entries = parse(SAMPLE, "journal.md");
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].text, "Slept badly. Standup moved to 10.");
        assert_eq!(
            entries[1].text,
            "Dinner with @nan.\nShe's taking the clinic job."
        );
    }

    #[test]
    fn text_before_the_first_heading_is_not_an_entry() {
        let entries = parse(SAMPLE, "journal.md");
        assert!(entries.iter().all(|e| !e.text.contains("preamble")));
    }

    /// A stated time and a stated date are not the same claim, and the basis
    /// travels with the entry so a footage window knows which it got.
    #[test]
    fn a_date_without_a_time_is_not_recorded_as_stated() {
        let entries = parse(SAMPLE, "journal.md");
        assert_eq!(entries[0].basis, TimeBasis::Stated);
        assert_eq!(entries[2].basis, TimeBasis::ParsedFromContent);
        assert_eq!(
            entries[2].at.time(),
            NaiveTime::from_hms_opt(12, 0, 0).unwrap()
        );
    }

    /// The property that makes appending cheap: an unchanged entry keeps its
    /// digest, so re-ingest is a no-op.
    #[test]
    fn appending_an_entry_leaves_the_others_digests_alone() {
        use ghostr_core::time::{Clock, Rng};

        struct Fixed;
        impl Clock for Fixed {
            fn now(&self) -> Timestamp {
                Timestamp::new(0, 0)
            }
            fn home_tz(&self) -> chrono_tz::Tz {
                chrono_tz::UTC
            }
        }
        struct Zero;
        impl Rng for Zero {
            fn fill(&self, buf: &mut [u8]) {
                buf.fill(0);
            }
        }

        let source = SourceId::new(1, [0u8; 10]);
        let before = parse(SAMPLE, "journal.md");
        let after = parse(
            &format!("{SAMPLE}\n## 2026-08-27 08:00\nNew entry.\n"),
            "journal.md",
        );
        assert_eq!(after.len(), before.len() + 1);
        for (a, b) in before.iter().zip(after.iter()) {
            assert_eq!(
                to_memory(a, source, &Fixed, &Zero).provenance.raw_hash,
                to_memory(b, source, &Fixed, &Zero).provenance.raw_hash
            );
        }
    }

    #[test]
    fn a_heading_with_no_body_produces_no_entry() {
        let entries = parse(
            "## 2026-08-25 09:14\n\n## 2026-08-26 10:00\nReal.\n",
            "j.md",
        );
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].text, "Real.");
    }

    /// A date that opens a sentence is content, not a heading.
    #[test]
    fn a_date_followed_by_prose_is_not_a_heading() {
        assert!(parse_heading("2026-08-25 was a long day").is_none());
        assert!(parse_heading("## 2026-08-25 was a long day").is_none());
    }

    #[test]
    fn bracketed_headings_are_accepted() {
        let entries = parse("[2026-08-25 07:30]\nUp early.\n", "j.txt");
        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0].at.time(),
            NaiveTime::from_hms_opt(7, 30, 0).unwrap()
        );
    }

    #[test]
    fn a_journal_is_first_party() {
        assert!(default_trust().may_be_exemplar());
    }
}
