//! The structured-log adapter: rows, not prose.
//!
//! Places visited, people seen, habits kept, health metrics, media consumed.
//! These arrive as exports — one JSON object per line — and they are worth
//! keeping typed rather than flattening into a sentence and hoping a model can
//! parse it back out.
//!
//! # One row shape, five schemas
//!
//! Every schema uses the same row:
//!
//! ```json
//! {"ts":"2026-08-25T09:14:00Z","subject":"clinic","detail":"annual checkup","value":"45","unit":"min"}
//! ```
//!
//! Only `ts` and `subject` are required. The [`LogSchema`] decides the
//! [`MemoryKind`], how the row reads as text, and how sensitive it is by
//! default. Five parsers for five near-identical shapes would be five places for
//! a timestamp bug to live.
//!
//! # Why `value` is a string
//!
//! The structured payload is canonical CBOR, which rejects floats on purpose:
//! one value must have exactly one encoding or the same row would hash two ways
//! (CLAUDE.md §5). Numbers therefore travel as the digits the export actually
//! wrote. `"45.0"` and `"45"` stay distinguishable, which is the honest outcome
//! — they are different strings in the source file.
//!
//! # Sensitivity
//!
//! [`suggested_sensitivity`] returns `Secret` for health and location logs. Where
//! someone sleeps and what their resting heart rate is are the two things in
//! this system a remote provider has the least business seeing, and the default
//! should not depend on a user reading a settings page. It is a suggestion made
//! at `ghostr source add`, not a floor applied at ingest: the value that governs
//! is the one recorded on the [`Source`](ghostr_core::source::Source).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use chrono::{NaiveDate, NaiveDateTime, NaiveTime};
use ghostr_core::hash::{Tag, tagged_hash};
use ghostr_core::ids::{MemoryId, SourceId};
use ghostr_core::memory::{Memory, MemoryBody, MemoryKind, Provenance, StructuredPayload};
use ghostr_core::sensitivity::{Sensitivity, TrustLevel};
use ghostr_core::source::{LogSchema, SourceKindTag};
use ghostr_core::time::{Clock, Rng, Timestamp};
use serde::{Deserialize, Serialize};

use crate::adapter::TimeBasis;

/// The source-kind tag this adapter registers under.
pub const KIND_TAG: &str = "structured_log";

/// One parsed row, before it becomes a [`Memory`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogRow {
    /// Which file it came from, relative to the scan root.
    pub relative_path: String,
    /// One-based line number, for error reporting. Never carries content.
    pub line: u32,
    /// When the row says it happened, in the user's local wall clock.
    pub at: NaiveDateTime,
    /// The typed payload.
    pub record: LogRecord,
}

/// The fields a structured-log row carries.
///
/// Serialised into the memory's [`StructuredPayload`], so field order and
/// encoding are fixed by canonical CBOR.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogRecord {
    /// What the row is about: a place, a person, a habit, a metric, a title.
    pub subject: String,
    /// Free-text elaboration.
    pub detail: Option<String>,
    /// A measurement, as the digits the export wrote.
    pub value: Option<String>,
    /// The measurement's unit.
    pub unit: Option<String>,
    /// Any other scalar fields the export carried, in key order.
    ///
    /// Kept rather than dropped: an export's extra column is usually the one
    /// thing that made the export worth having.
    pub extra: BTreeMap<String, String>,
}

/// How a file of rows parsed.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ScanReport {
    /// Rows that parsed.
    pub rows: Vec<LogRow>,
    /// Lines that did not.
    ///
    /// Counted rather than fatal: one malformed line in a five-year health
    /// export should not abort the import. The count reaches the user; the line
    /// contents never do.
    pub unparseable: u32,
}

/// The wire shape of one line.
#[derive(Deserialize)]
struct WireRow {
    ts: String,
    subject: String,
    #[serde(default)]
    detail: Option<String>,
    #[serde(default)]
    value: Option<serde_json::Value>,
    #[serde(default)]
    unit: Option<String>,
    #[serde(flatten)]
    extra: BTreeMap<String, serde_json::Value>,
}

/// Reads every row from a JSONL file, or from every `.jsonl` file under a
/// directory.
///
/// # Errors
///
/// Returns [`Error::Unreachable`](crate::Error::Unreachable) if the path does
/// not exist or cannot be read.
pub fn scan(root: &Path, source: SourceId) -> crate::Result<ScanReport> {
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
                p.extension().is_some_and(|e| {
                    e.eq_ignore_ascii_case("jsonl") || e.eq_ignore_ascii_case("ndjson")
                })
            })
            .collect()
    } else {
        return Err(crate::Error::Unreachable { id: source });
    };
    files.sort();

    let mut report = ScanReport::default();
    for path in files {
        let Ok(raw) = std::fs::read_to_string(&path) else {
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
        let file = parse(&raw, &relative_path);
        report.rows.extend(file.rows);
        report.unparseable += file.unparseable;
    }
    Ok(report)
}

/// Parses JSONL text into rows.
#[must_use]
pub fn parse(raw: &str, relative_path: &str) -> ScanReport {
    let mut report = ScanReport::default();
    for (index, line) in raw.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let number = u32::try_from(index + 1).unwrap_or(u32::MAX);
        match serde_json::from_str::<WireRow>(line).ok().and_then(|wire| {
            let at = parse_timestamp(&wire.ts)?;
            Some(LogRow {
                relative_path: relative_path.to_owned(),
                line: number,
                at,
                record: LogRecord {
                    subject: wire.subject,
                    detail: wire.detail,
                    value: wire.value.as_ref().and_then(scalar),
                    unit: wire.unit,
                    extra: wire
                        .extra
                        .iter()
                        .filter_map(|(k, v)| Some((k.clone(), scalar(v)?)))
                        .collect(),
                },
            })
        }) {
            Some(row) => report.rows.push(row),
            None => report.unparseable += 1,
        }
    }
    report
}

/// Renders a JSON scalar as the text the export wrote.
///
/// Objects and arrays return `None`: a nested structure is not a column value,
/// and stringifying one would put a JSON fragment into a memory body.
fn scalar(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::String(s) => Some(s.clone()),
        // `Number::to_string` reproduces the literal serde_json parsed, so `45`
        // and `45.0` stay distinct — which they are, in the source file.
        serde_json::Value::Number(n) => Some(n.to_string()),
        serde_json::Value::Bool(b) => Some(b.to_string()),
        serde_json::Value::Null | serde_json::Value::Array(_) | serde_json::Value::Object(_) => {
            None
        }
    }
}

/// Accepts RFC 3339, `YYYY-MM-DD HH:MM[:SS]`, and a bare `YYYY-MM-DD`.
///
/// A bare date lands at local noon, far enough from either cutoff that a
/// timezone shift cannot move the row into the adjacent day.
fn parse_timestamp(raw: &str) -> Option<NaiveDateTime> {
    let raw = raw.trim();
    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(raw) {
        return Some(dt.naive_utc());
    }
    for format in [
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%dT%H:%M",
    ] {
        if let Ok(dt) = NaiveDateTime::parse_from_str(raw, format) {
            return Some(dt);
        }
    }
    raw.parse::<NaiveDate>()
        .ok()
        .and_then(|d| Some(NaiveDateTime::new(d, NaiveTime::from_hms_opt(12, 0, 0)?)))
}

/// How a row reads as text.
///
/// The text is what a summariser and a retrieval query see, so it is a plain
/// sentence rather than a serialisation. The typed payload travels alongside it
/// for anything that needs the fields back.
#[must_use]
pub fn render(schema: LogSchema, record: &LogRecord) -> String {
    let measure = match (&record.value, &record.unit) {
        (Some(v), Some(u)) => format!(" ({v} {u})"),
        (Some(v), None) => format!(" ({v})"),
        _ => String::new(),
    };
    let detail = record
        .detail
        .as_ref()
        .map(|d| format!(" — {d}"))
        .unwrap_or_default();
    let subject = &record.subject;
    match schema {
        LogSchema::Places => format!("At {subject}{measure}{detail}"),
        LogSchema::People => format!("Saw {subject}{measure}{detail}"),
        LogSchema::Habits => format!("Habit: {subject}{measure}{detail}"),
        LogSchema::Health => format!("Health: {subject}{measure}{detail}"),
        LogSchema::Media => format!("Media: {subject}{measure}{detail}"),
        _ => format!("{subject}{measure}{detail}"),
    }
}

/// The memory kind a schema's rows produce.
#[must_use]
pub const fn memory_kind(schema: LogSchema) -> MemoryKind {
    match schema {
        LogSchema::Places => MemoryKind::Location,
        LogSchema::People => MemoryKind::Relationship,
        LogSchema::Habits => MemoryKind::Habit,
        LogSchema::Health => MemoryKind::Observation,
        LogSchema::Media => MemoryKind::Artifact,
        // `LogSchema` is `#[non_exhaustive]`. An unrecognised schema is recorded
        // as a plain observation rather than guessed at.
        _ => MemoryKind::Observation,
    }
}

/// The sensitivity to suggest when a source of this schema is added.
///
/// Health and location default to `Secret` — never egresses, local models only.
/// That is the right default for the two categories a user would least like to
/// discover in a provider's logs, and defaults are what most people keep.
#[must_use]
pub const fn suggested_sensitivity(schema: LogSchema) -> Sensitivity {
    match schema {
        LogSchema::Health | LogSchema::Places => Sensitivity::Secret,
        LogSchema::People | LogSchema::Habits | LogSchema::Media => Sensitivity::Private,
        // Fail closed on a schema this build does not recognise.
        _ => Sensitivity::Secret,
    }
}

/// Converts a parsed row into a memory.
///
/// # Errors
///
/// Returns [`Error::Unparseable`](crate::Error::Unparseable) if the record does
/// not encode as canonical CBOR. The error carries the file and line, never the
/// row.
pub fn to_memory(
    row: &LogRow,
    schema: LogSchema,
    source: SourceId,
    clock: &dyn Clock,
    rng: &dyn Rng,
) -> crate::Result<Memory> {
    let now = clock.now();
    let text = render(schema, &row.record);

    let cbor = ghostr_core::canonical::to_canonical_cbor(&row.record).map_err(|_| {
        crate::Error::Unparseable {
            id: source,
            location: format!("{}:{}", row.relative_path, row.line),
        }
    })?;
    let structured = StructuredPayload::new(cbor).map_err(|_| crate::Error::Unparseable {
        id: source,
        location: format!("{}:{}", row.relative_path, row.line),
    })?;

    // Over the canonical payload rather than the rendered text: two rows that
    // differ only in a field the renderer drops are still two rows.
    let raw_hash = tagged_hash(Tag::MemoryLeaf, structured.as_bytes());

    let mut random = [0u8; 10];
    rng.fill(&mut random);
    let mut salt = [0u8; 32];
    rng.fill(&mut salt);

    Ok(Memory {
        id: MemoryId::new(now.utc_millis().unsigned_abs(), random),
        source_id: source,
        occurred_at: Some(Timestamp::new(row.at.and_utc().timestamp_millis(), 0)),
        ingested_at: now,
        kind: memory_kind(schema),
        body: MemoryBody {
            text,
            structured: Some(structured),
            redactions: Vec::new(),
        },
        entities: Vec::new(),
        // A logged row is a fact, not a story. Uniform salience keeps the
        // deterministic recap from ranking a step count above a diary entry.
        salience: 0.4,
        sensitivity: suggested_sensitivity(schema),
        provenance: Provenance {
            source_id: source,
            external_id: Some(format!("{}:{}", row.relative_path, row.line)),
            url: None,
            raw_hash,
        },
        salt,
        supersedes: None,
        embedding: None,
    })
}

/// How a row's occurrence time was determined.
#[must_use]
pub const fn time_basis() -> TimeBasis {
    TimeBasis::Stated
}

/// The trust level structured-log content carries.
///
/// [`TrustLevel::SelfReported`], not [`TrustLevel::FirstParty`]: a health export
/// is the user asserting something about themselves, and a step count is not a
/// sentence they wrote. It may source a stance; it may never be a voice
/// exemplar (THREAT_MODEL §T7).
#[must_use]
pub const fn default_trust() -> TrustLevel {
    TrustLevel::SelfReported
}

/// The source-kind tag.
#[must_use]
pub const fn kind() -> SourceKindTag {
    SourceKindTag::StructuredLog
}

/// The structured-log source, as an [`IngestAdapter`](crate::IngestAdapter).
pub struct StructLogAdapter {
    clock: std::sync::Arc<dyn Clock>,
    rng: std::sync::Arc<dyn Rng>,
}

impl core::fmt::Debug for StructLogAdapter {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("StructLogAdapter")
    }
}

impl StructLogAdapter {
    /// Builds the adapter over an injected clock and entropy source.
    #[must_use]
    pub fn new(clock: std::sync::Arc<dyn Clock>, rng: std::sync::Arc<dyn Rng>) -> Self {
        Self { clock, rng }
    }
}

/// How many rows one pull returns.
///
/// A five-year health export is millions of rows. Bounded batches are what make
/// an import resumable rather than an all-or-nothing operation that has to
/// survive a laptop lid closing.
const BATCH_ROWS: usize = 512;

#[async_trait::async_trait]
impl crate::adapter::IngestAdapter for StructLogAdapter {
    fn kind(&self) -> SourceKindTag {
        SourceKindTag::StructuredLog
    }

    async fn pull(
        &self,
        source: &ghostr_core::source::Source,
        cursor: ghostr_core::source::SyncCursor,
    ) -> crate::Result<crate::adapter::IngestBatch> {
        use ghostr_core::source::SyncCursor;

        let ghostr_core::source::SourceKind::StructuredLog { schema, path } = &source.kind else {
            return Err(crate::Error::InvalidCursor { id: source.id });
        };
        let after = match cursor {
            SyncCursor::Start => i64::MIN,
            SyncCursor::Timestamp(t) => t.utc_millis(),
            SyncCursor::Complete => return Ok(empty_batch(SyncCursor::Complete)),
            // A file-mtime or opaque cursor belongs to another adapter. Refusing
            // beats guessing: proceeding would re-import from the start or skip
            // a span, and both are worse than stopping.
            SyncCursor::FileMtime(_) | SyncCursor::Opaque(_) => {
                return Err(crate::Error::InvalidCursor { id: source.id });
            }
            _ => return Err(crate::Error::InvalidCursor { id: source.id }),
        };

        let report = scan(Path::new(path), source.id)?;
        let mut pending: Vec<LogRow> = report
            .rows
            .into_iter()
            .filter(|r| r.at.and_utc().timestamp_millis() >= after)
            .collect();
        // Deterministic order, so a resumed import continues where it stopped
        // rather than wherever the filesystem happened to hand back.
        pending.sort_by(|a, b| {
            a.at.cmp(&b.at)
                .then_with(|| a.relative_path.cmp(&b.relative_path))
                .then_with(|| a.line.cmp(&b.line))
        });

        let has_more = pending.len() > BATCH_ROWS;
        pending.truncate(BATCH_ROWS);

        let mut memories = Vec::with_capacity(pending.len());
        let mut unparseable = report.unparseable;
        for row in &pending {
            match to_memory(
                row,
                *schema,
                source.id,
                self.clock.as_ref(),
                self.rng.as_ref(),
            ) {
                Ok(memory) => memories.push(memory),
                // A row that will not encode canonically is counted, not fatal.
                Err(_) => unparseable += 1,
            }
        }

        // Inclusive: the cursor sits *on* the last row taken rather than past
        // it, so rows sharing that instant cannot be skipped. The repeat is
        // absorbed by the store's digest index.
        let next = pending.last().map_or(cursor, |row| {
            SyncCursor::Timestamp(Timestamp::new(row.at.and_utc().timestamp_millis(), 0))
        });

        Ok(crate::adapter::IngestBatch {
            memories,
            cursor: next,
            has_more,
            duplicates_skipped: 0,
            unparseable_skipped: unparseable,
        })
    }

    fn default_trust(&self) -> TrustLevel {
        default_trust()
    }

    fn default_sensitivity(&self) -> Sensitivity {
        // The strictest across schemas. This method does not know which schema a
        // source uses, and the safe answer to "which of these is it" is the one
        // that cannot egress. `suggested_sensitivity` refines it once the schema
        // is known.
        Sensitivity::Secret
    }

    fn touches_network(&self) -> bool {
        false
    }

    async fn validate(&self, source: &ghostr_core::source::Source) -> crate::Result<()> {
        let ghostr_core::source::SourceKind::StructuredLog { path, .. } = &source.kind else {
            return Err(crate::Error::InvalidCursor { id: source.id });
        };
        let path = Path::new(path);
        if path.is_file() || path.is_dir() {
            Ok(())
        } else {
            Err(crate::Error::Unreachable { id: source.id })
        }
    }
}

/// A batch with nothing in it, leaving the cursor where it was.
fn empty_batch(cursor: ghostr_core::source::SyncCursor) -> crate::adapter::IngestBatch {
    crate::adapter::IngestBatch {
        memories: Vec::new(),
        cursor,
        has_more: false,
        duplicates_skipped: 0,
        unparseable_skipped: 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(super) struct Fixed;
    impl Clock for Fixed {
        fn now(&self) -> Timestamp {
            Timestamp::new(1_700_000_000_000, 0)
        }
        fn home_tz(&self) -> chrono_tz::Tz {
            chrono_tz::UTC
        }
    }
    pub(super) struct Zero;
    impl Rng for Zero {
        fn fill(&self, buf: &mut [u8]) {
            buf.fill(0);
        }
    }

    const SAMPLE: &str = r#"
{"ts":"2026-08-25T09:14:00Z","subject":"clinic","detail":"annual checkup","value":45,"unit":"min"}
{"ts":"2026-08-25 18:00","subject":"resting hr","value":58,"unit":"bpm","device":"watch"}
not json at all
{"subject":"missing a timestamp"}
{"ts":"2026-08-26","subject":"gym"}
"#;

    #[test]
    fn rows_parse_and_bad_lines_are_counted_not_fatal() {
        let report = parse(SAMPLE, "health.jsonl");
        assert_eq!(report.rows.len(), 3);
        assert_eq!(report.unparseable, 2);
    }

    /// The count is the only thing that escapes. A malformed line is often
    /// exactly the line you would least like copied into a log (I8).
    #[test]
    fn an_unparseable_line_never_reaches_an_error_message() {
        let source = SourceId::new(1, [0u8; 10]);
        let err = crate::Error::Unparseable {
            id: source,
            location: "health.jsonl:3".to_owned(),
        };
        assert!(!format!("{err}").contains("not json at all"));
    }

    #[test]
    fn extra_columns_are_kept_in_key_order() {
        let report = parse(SAMPLE, "health.jsonl");
        let extra = &report.rows[1].record.extra;
        assert_eq!(extra.get("device").map(String::as_str), Some("watch"));
    }

    /// The reason `value` is a string: canonical CBOR rejects floats, and it
    /// must, or the same row would hash two ways (CLAUDE.md §5).
    #[test]
    fn a_decimal_measurement_survives_canonical_encoding() {
        let report = parse(
            r#"{"ts":"2026-08-25","subject":"weight","value":72.5,"unit":"kg"}"#,
            "h.jsonl",
        );
        assert_eq!(report.rows[0].record.value.as_deref(), Some("72.5"));
        let memory = to_memory(
            &report.rows[0],
            LogSchema::Health,
            SourceId::new(1, [0u8; 10]),
            &Fixed,
            &Zero,
        )
        .expect("canonical encoding");
        let decoded: LogRecord = memory
            .body
            .structured
            .as_ref()
            .expect("payload")
            .decode()
            .expect("decode");
        assert_eq!(decoded.value.as_deref(), Some("72.5"));
    }

    #[test]
    fn timestamps_accept_the_three_shapes_exports_actually_use() {
        assert!(parse_timestamp("2026-08-25T09:14:00Z").is_some());
        assert!(parse_timestamp("2026-08-25 18:00").is_some());
        let noon = parse_timestamp("2026-08-26").expect("bare date");
        assert_eq!(noon.time(), NaiveTime::from_hms_opt(12, 0, 0).unwrap());
    }

    /// Health and location default to never leaving the device.
    #[test]
    fn health_and_places_suggest_secret() {
        assert_eq!(
            suggested_sensitivity(LogSchema::Health),
            Sensitivity::Secret
        );
        assert_eq!(
            suggested_sensitivity(LogSchema::Places),
            Sensitivity::Secret
        );
        assert!(!suggested_sensitivity(LogSchema::Health).may_egress());
        assert_eq!(
            suggested_sensitivity(LogSchema::Media),
            Sensitivity::Private
        );
    }

    /// A step count is not a sentence the user wrote (THREAT_MODEL §T7).
    #[test]
    fn a_structured_log_is_never_a_voice_exemplar() {
        assert!(!default_trust().may_be_exemplar());
        assert!(default_trust().may_source_stance());
    }

    #[test]
    fn a_row_reads_as_a_sentence_not_a_serialisation() {
        let report = parse(SAMPLE, "health.jsonl");
        let text = render(LogSchema::Places, &report.rows[0].record);
        assert_eq!(text, "At clinic (45 min) — annual checkup");
        assert!(!text.contains('{'));
    }

    /// Re-ingesting an unchanged export must be a no-op, which needs the digest
    /// to be stable across runs.
    #[test]
    fn an_unchanged_row_keeps_its_digest() {
        let source = SourceId::new(1, [0u8; 10]);
        let a = parse(SAMPLE, "health.jsonl");
        let b = parse(SAMPLE, "health.jsonl");
        for (x, y) in a.rows.iter().zip(b.rows.iter()) {
            let mx = to_memory(x, LogSchema::Health, source, &Fixed, &Zero).expect("a");
            let my = to_memory(y, LogSchema::Health, source, &Fixed, &Zero).expect("b");
            assert_eq!(mx.provenance.raw_hash, my.provenance.raw_hash);
        }
    }

    #[test]
    fn a_nested_object_is_not_flattened_into_the_body() {
        let report = parse(
            r#"{"ts":"2026-08-25","subject":"walk","route":{"from":"home","to":"clinic"}}"#,
            "p.jsonl",
        );
        assert!(report.rows[0].record.extra.is_empty());
        assert!(!render(LogSchema::Places, &report.rows[0].record).contains("home"));
    }
}

#[cfg(test)]
mod adapter_tests {
    use std::sync::Arc;

    use ghostr_core::source::{IngestSchedule, RedactionPolicy, Source, SourceKind, SyncCursor};

    use super::tests::{Fixed, Zero};
    use super::*;
    use crate::adapter::IngestAdapter as _;

    fn source(path: &Path) -> Source {
        Source {
            id: SourceId::new(1, [0u8; 10]),
            kind: SourceKind::StructuredLog {
                schema: LogSchema::Health,
                path: path.display().to_string(),
            },
            trust: default_trust(),
            default_sensitivity: Sensitivity::Secret,
            cursor: SyncCursor::Start,
            schedule: IngestSchedule::Manual,
            redaction: RedactionPolicy {
                detect_secrets: true,
                patterns: Vec::new(),
                minimum_sensitivity: None,
            },
            enabled: true,
            last_sync: None,
        }
    }

    fn adapter() -> StructLogAdapter {
        StructLogAdapter::new(Arc::new(Fixed), Arc::new(Zero))
    }

    fn write(dir: &Path, lines: &str) -> PathBuf {
        let path = dir.join("health.jsonl");
        std::fs::write(&path, lines).expect("write");
        path
    }

    #[tokio::test]
    async fn a_pull_produces_memories_and_advances_the_cursor() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = write(
            dir.path(),
            "{\"ts\":\"2026-08-25 09:00\",\"subject\":\"a\"}\n{\"ts\":\"2026-08-26 09:00\",\"subject\":\"b\"}\n",
        );
        let batch = adapter()
            .pull(&source(&path), SyncCursor::Start)
            .await
            .expect("pull");
        assert_eq!(batch.memories.len(), 2);
        assert!(!batch.has_more);
        assert!(matches!(batch.cursor, SyncCursor::Timestamp(_)));
    }

    /// Resuming re-reads the row the cursor sits on rather than stepping past
    /// it. The repeat is absorbed by the store's digest index; a skipped row
    /// would be lost for good.
    #[tokio::test]
    async fn resuming_from_a_cursor_does_not_skip_the_row_it_sits_on() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = write(
            dir.path(),
            "{\"ts\":\"2026-08-25 09:00\",\"subject\":\"a\"}\n{\"ts\":\"2026-08-25 09:00\",\"subject\":\"b\"}\n",
        );
        let first = adapter()
            .pull(&source(&path), SyncCursor::Start)
            .await
            .expect("pull");
        let again = adapter()
            .pull(&source(&path), first.cursor)
            .await
            .expect("resume");
        assert_eq!(
            again.memories.len(),
            2,
            "both rows share the cursor instant"
        );
    }

    /// A cursor from another adapter is refused rather than guessed at.
    #[tokio::test]
    async fn a_foreign_cursor_is_refused() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = write(dir.path(), "{\"ts\":\"2026-08-25\",\"subject\":\"a\"}\n");
        let err = adapter()
            .pull(&source(&path), SyncCursor::FileMtime(Timestamp::new(0, 0)))
            .await
            .expect_err("must refuse");
        assert!(matches!(err, crate::Error::InvalidCursor { .. }));
    }

    #[tokio::test]
    async fn validate_rejects_a_path_that_is_not_there() {
        let missing = Path::new("/nonexistent/health.jsonl");
        let err = adapter()
            .validate(&source(missing))
            .await
            .expect_err("must fail");
        assert!(matches!(err, crate::Error::Unreachable { .. }));
    }
}
