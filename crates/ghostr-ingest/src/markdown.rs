//! The markdown vault adapter.
//!
//! Walks a directory, turns each `.md` file into one [`Memory`], and derives an
//! occurrence date from the strongest available signal.
//!
//! # Dating a note
//!
//! In descending order of trust, recorded as a [`TimeBasis`]:
//!
//! 1. A `date:` line in YAML front matter — the user said so.
//! 2. A `YYYY-MM-DD` prefix in the filename — the user's own convention.
//! 3. Filesystem mtime — a guess, and recorded as one.
//!
//! The distinction matters because footage windows are built from these
//! timestamps. A footage assembled from mtimes should not claim the same
//! authority as one assembled from dates the user wrote down, so the basis
//! travels with the memory rather than being flattened away.

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
pub const KIND_TAG: &str = "markdown_vault";

/// One parsed note, before it becomes a [`Memory`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedNote {
    /// Path relative to the vault root.
    pub relative_path: String,
    /// The note body, front matter stripped.
    pub text: String,
    /// The date the note is about.
    pub date: NaiveDate,
    /// How that date was determined.
    pub basis: TimeBasis,
}

/// Reads every markdown file under `root`, in a stable order.
///
/// Ordering is by path, so two runs over an unchanged vault produce memories in
/// the same order — which keeps ingest reproducible and makes the resulting
/// footage byte-identical.
///
/// # Errors
///
/// Returns [`Error::Unreachable`](crate::Error::Unreachable) if the root cannot
/// be read.
pub fn scan_vault(root: &Path, source: SourceId) -> crate::Result<Vec<ParsedNote>> {
    if !root.is_dir() {
        return Err(crate::Error::Unreachable { id: source });
    }
    let mut paths: Vec<PathBuf> = walkdir::WalkDir::new(root)
        .follow_links(false)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|e| e.file_type().is_file())
        .map(walkdir::DirEntry::into_path)
        .filter(|p| p.extension().is_some_and(|e| e.eq_ignore_ascii_case("md")))
        .collect();
    paths.sort();

    let mut out = Vec::with_capacity(paths.len());
    for path in paths {
        let Ok(raw) = std::fs::read_to_string(&path) else {
            // A file that is not UTF-8 is skipped rather than fatal: one binary
            // blob with an .md extension should not abort a vault import.
            continue;
        };
        let relative_path = path
            .strip_prefix(root)
            .unwrap_or(&path)
            .to_string_lossy()
            .replace('\\', "/");
        let (front_matter_date, body) = split_front_matter(&raw);
        let (date, basis) = match front_matter_date.or_else(|| {
            date_from_filename(&relative_path).map(|d| (d, TimeBasis::ParsedFromContent))
        }) {
            Some((d, b)) => (d, b),
            None => (mtime_date(&path), TimeBasis::FileMtime),
        };
        out.push(ParsedNote {
            relative_path,
            text: body.trim().to_owned(),
            date,
            basis,
        });
    }
    Ok(out)
}

/// Converts a parsed note into a memory.
///
/// `raw_hash` is taken over the note's path and body, so re-ingesting an
/// unchanged vault produces the same digest and the store's unique index makes
/// the second run a no-op.
#[must_use]
pub fn to_memory(note: &ParsedNote, source: SourceId, clock: &dyn Clock, rng: &dyn Rng) -> Memory {
    let now = clock.now();
    let raw_hash = tagged_hash(
        Tag::MemoryLeaf,
        format!("{}\u{0}{}", note.relative_path, note.text).as_bytes(),
    );

    // Notes are dated but not timed, so they land at local noon: far enough from
    // either cutoff boundary that a timezone shift cannot move a note into the
    // adjacent day.
    let at = NaiveDateTime::new(
        note.date,
        NaiveTime::from_hms_opt(12, 0, 0).unwrap_or_default(),
    );
    let occurred = Timestamp::new(at.and_utc().timestamp_millis(), 0);

    let mut random = [0u8; 10];
    rng.fill(&mut random);
    let mut salt = [0u8; 32];
    rng.fill(&mut salt);

    Memory {
        id: MemoryId::new(now.utc_millis().unsigned_abs(), random),
        source_id: source,
        occurred_at: Some(occurred),
        ingested_at: now,
        kind: MemoryKind::Utterance,
        body: MemoryBody {
            text: note.text.clone(),
            structured: None,
            redactions: Vec::new(),
        },
        entities: Vec::new(),
        salience: salience_of(&note.text),
        sensitivity: Sensitivity::Private,
        provenance: Provenance {
            source_id: source,
            external_id: Some(note.relative_path.clone()),
            url: None,
            raw_hash,
        },
        salt,
        supersedes: None,
        embedding: None,
    }
}

/// A deterministic salience score in `0.0..=1.0`.
///
/// Longer notes and notes carrying explicit markers score higher. Crude on
/// purpose: M0 has no model, and a transparent heuristic that a reader can
/// predict is better than an opaque one they cannot.
#[must_use]
pub fn salience_of(text: &str) -> f32 {
    let words = text.split_whitespace().count();
    let length_score = (words as f32 / 200.0).min(1.0);
    let marker_bonus = f32::from(u8::from(
        text.contains("TODO") || text.contains('!') || text.contains("- [ ]"),
    )) * 0.2;
    (0.3 + length_score * 0.5 + marker_bonus).min(1.0)
}

/// Splits YAML front matter off the top of a note, returning any `date:` in it.
fn split_front_matter(raw: &str) -> (Option<(NaiveDate, TimeBasis)>, String) {
    let Some(rest) = raw.strip_prefix("---\n") else {
        return (None, raw.to_owned());
    };
    let Some(end) = rest.find("\n---") else {
        return (None, raw.to_owned());
    };
    let (front, body) = rest.split_at(end);
    let date = front.lines().find_map(|line| {
        let value = line.strip_prefix("date:")?.trim().trim_matches(['"', '\'']);
        value
            .parse::<NaiveDate>()
            .ok()
            .map(|d| (d, TimeBasis::Stated))
    });
    (
        date,
        body.trim_start_matches("\n---").trim_start().to_owned(),
    )
}

/// Extracts a leading `YYYY-MM-DD` from a filename.
fn date_from_filename(relative_path: &str) -> Option<NaiveDate> {
    let name = relative_path.rsplit('/').next().unwrap_or(relative_path);
    name.get(..10)
        .and_then(|prefix| prefix.parse::<NaiveDate>().ok())
}

/// Falls back to filesystem mtime.
fn mtime_date(path: &Path) -> NaiveDate {
    std::fs::metadata(path)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .and_then(|d| {
            chrono::DateTime::from_timestamp(i64::try_from(d.as_secs()).unwrap_or_default(), 0)
        })
        .map(|dt| dt.date_naive())
        .unwrap_or_default()
}

/// The trust level markdown vault content carries.
///
/// [`TrustLevel::FirstParty`]: the user wrote these notes themselves. That is
/// what makes them eligible as voice exemplars, and it is why an adapter for a
/// *feed* must never return this (THREAT_MODEL §T7).
#[must_use]
pub const fn default_trust() -> TrustLevel {
    TrustLevel::FirstParty
}

/// The source-kind tag.
#[must_use]
pub const fn kind() -> SourceKindTag {
    SourceKindTag::MarkdownVault
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(dir: &Path, name: &str, body: &str) {
        let path = dir.join(name);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("mkdir");
        }
        std::fs::write(path, body).expect("write");
    }

    #[test]
    fn front_matter_date_wins_over_the_filename() {
        let dir = tempfile::tempdir().expect("tempdir");
        write(
            dir.path(),
            "2020-01-01-note.md",
            "---\ndate: 2026-08-25\n---\nbody text\n",
        );
        let notes = scan_vault(dir.path(), SourceId::new(1, [0u8; 10])).expect("scan");
        assert_eq!(notes.len(), 1);
        assert_eq!(
            notes[0].date,
            "2026-08-25".parse::<NaiveDate>().expect("date")
        );
        assert_eq!(notes[0].basis, TimeBasis::Stated);
        assert_eq!(notes[0].text, "body text");
    }

    #[test]
    fn filename_date_is_used_when_there_is_no_front_matter() {
        let dir = tempfile::tempdir().expect("tempdir");
        write(dir.path(), "2026-08-25-standup.md", "just a note");
        let notes = scan_vault(dir.path(), SourceId::new(1, [0u8; 10])).expect("scan");
        assert_eq!(
            notes[0].date,
            "2026-08-25".parse::<NaiveDate>().expect("date")
        );
        assert_eq!(notes[0].basis, TimeBasis::ParsedFromContent);
    }

    #[test]
    fn an_undated_note_falls_back_to_mtime_and_says_so() {
        let dir = tempfile::tempdir().expect("tempdir");
        write(dir.path(), "thoughts.md", "no date anywhere");
        let notes = scan_vault(dir.path(), SourceId::new(1, [0u8; 10])).expect("scan");
        assert_eq!(notes[0].basis, TimeBasis::FileMtime);
    }

    #[test]
    fn the_scan_is_ordered_and_recursive() {
        let dir = tempfile::tempdir().expect("tempdir");
        write(dir.path(), "b.md", "second");
        write(dir.path(), "a.md", "first");
        write(dir.path(), "nested/c.md", "third");
        write(dir.path(), "ignored.txt", "not markdown");

        let notes = scan_vault(dir.path(), SourceId::new(1, [0u8; 10])).expect("scan");
        let paths: Vec<_> = notes.iter().map(|n| n.relative_path.as_str()).collect();
        assert_eq!(paths, vec!["a.md", "b.md", "nested/c.md"]);
    }

    #[test]
    fn raw_hash_is_stable_across_runs_but_changes_with_content() {
        let dir = tempfile::tempdir().expect("tempdir");
        write(dir.path(), "a.md", "---\ndate: 2026-08-25\n---\noriginal");
        let src = SourceId::new(1, [0u8; 10]);
        let clock = FixedClock;
        let rng = ZeroRng;

        let first = scan_vault(dir.path(), src).expect("scan");
        let m1 = to_memory(&first[0], src, &clock, &rng);
        let second = scan_vault(dir.path(), src).expect("scan");
        let m2 = to_memory(&second[0], src, &clock, &rng);
        // Re-ingesting an unchanged vault must produce the same digest, which is
        // what makes the store's unique index turn it into a no-op.
        assert_eq!(m1.provenance.raw_hash, m2.provenance.raw_hash);

        write(dir.path(), "a.md", "---\ndate: 2026-08-25\n---\nedited");
        let third = scan_vault(dir.path(), src).expect("scan");
        let m3 = to_memory(&third[0], src, &clock, &rng);
        assert_ne!(m1.provenance.raw_hash, m3.provenance.raw_hash);
    }

    #[test]
    fn salience_rises_with_length_and_markers() {
        assert!(salience_of("short") < salience_of(&"word ".repeat(200)));
        assert!(salience_of("plain") < salience_of("plain TODO"));
        assert!(salience_of(&"word ".repeat(500)) <= 1.0);
    }

    struct FixedClock;
    impl Clock for FixedClock {
        fn now(&self) -> Timestamp {
            Timestamp::new(1_700_000_000_000, 0)
        }
        fn home_tz(&self) -> chrono_tz::Tz {
            chrono_tz::UTC
        }
    }

    struct ZeroRng;
    impl Rng for ZeroRng {
        fn fill(&self, buf: &mut [u8]) {
            buf.fill(0);
        }
    }
}
