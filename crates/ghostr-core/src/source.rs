//! [`Source`] — a place memories come from.
//!
//! Sources carry two policy fields that matter more than the rest of the type
//! put together: [`Source::default_sensitivity`], which sets the ceiling on
//! where this content may travel, and [`Source::trust`], which decides whether
//! the content is treated as the user's own voice or as hostile input
//! (THREAT_MODEL §T7).

use serde::{Deserialize, Serialize};

use crate::ids::SourceId;
use crate::sensitivity::{Sensitivity, TrustLevel};
use crate::time::Timestamp;

/// A configured data source.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Source {
    /// Stable identifier.
    pub id: SourceId,
    /// What kind of source this is, and how to reach it.
    pub kind: SourceKind,
    /// How much the content is trusted. A security control, not a quality score.
    pub trust: TrustLevel,
    /// Sensitivity floor for memories from this source.
    ///
    /// Per-memory sensitivity may be raised above this by later processing, and
    /// never lowered below it.
    pub default_sensitivity: Sensitivity,
    /// Resumable position in the source.
    pub cursor: SyncCursor,
    /// How often to pull.
    pub schedule: IngestSchedule,
    /// What to strip before storage.
    pub redaction: RedactionPolicy,
    /// Whether this source is currently pulled.
    pub enabled: bool,
    /// Outcome of the most recent pull.
    pub last_sync: Option<SyncReport>,
}

/// What kind of source, and how to reach it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "type")]
#[non_exhaustive]
pub enum SourceKind {
    /// A nostr feed.
    NostrFeed {
        /// Whose feed. Hex x-only pubkey.
        pubkey: String,
        /// Relays to read from.
        relays: Vec<String>,
        /// Event kinds to pull.
        kinds: Vec<u16>,
    },
    /// An RSS or Atom feed.
    Rss {
        /// Feed URL.
        url: String,
        /// Last `ETag`, for conditional fetches.
        etag: Option<String>,
    },
    /// An exported social archive: X/Twitter, Mastodon, Reddit.
    SocialArchive {
        /// Which export format.
        format: ArchiveFormat,
        /// Path to the archive on disk.
        path: String,
    },
    /// A directory of markdown notes.
    MarkdownVault {
        /// Vault root.
        root: String,
        /// Glob selecting files within the root.
        glob: String,
    },
    /// Entries typed directly into Ghostr, or imported into its journal.
    ///
    /// Carries no location because it has none: journal entries live in the
    /// encrypted store from the moment they are made. Ghostr never writes a
    /// plaintext journal file (I1).
    Journal,
    /// A structured log: places, people, habits, health.
    StructuredLog {
        /// Which log schema the rows conform to.
        schema: LogSchema,
        /// The JSONL file, or a directory of them.
        path: String,
    },
}

/// A tag identifying a [`SourceKind`] without its payload.
///
/// Used by adapter registration, where the configuration is not yet known.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum SourceKindTag {
    /// [`SourceKind::NostrFeed`].
    NostrFeed,
    /// [`SourceKind::Rss`].
    Rss,
    /// [`SourceKind::SocialArchive`].
    SocialArchive,
    /// [`SourceKind::MarkdownVault`].
    MarkdownVault,
    /// [`SourceKind::Journal`].
    Journal,
    /// [`SourceKind::StructuredLog`].
    StructuredLog,
}

/// Which social export format an archive is in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ArchiveFormat {
    /// X/Twitter data export.
    TwitterX,
    /// Mastodon export.
    Mastodon,
    /// Reddit GDPR export.
    Reddit,
    /// A generic GDPR dump handled by the fallback importer.
    GenericGdpr,
}

/// Which structured-log schema a source's rows conform to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum LogSchema {
    /// Places visited, with times.
    Places,
    /// People seen or contacted.
    People,
    /// Habit and streak tracking.
    Habits,
    /// Health and activity metrics.
    Health,
    /// Media consumed.
    Media,
}

/// A resumable position within a source.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "type")]
#[non_exhaustive]
pub enum SyncCursor {
    /// Nothing pulled yet.
    Start,
    /// Everything up to this instant has been pulled.
    Timestamp(Timestamp),
    /// Everything up to this opaque source-defined token has been pulled.
    Opaque(String),
    /// Files modified at or before this instant have been pulled.
    FileMtime(Timestamp),
    /// The source is exhausted: a one-shot archive import that finished.
    Complete,
}

/// How often a source is pulled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "type")]
#[non_exhaustive]
pub enum IngestSchedule {
    /// Only when the user asks.
    Manual,
    /// Every `minutes`.
    Interval {
        /// Period in minutes.
        minutes: u32,
    },
    /// Once per day, ahead of the sealing cutoff.
    Daily,
    /// Continuously, for sources that push (an open relay subscription).
    Continuous,
}

/// What to strip from a source's content before it is stored.
///
/// Redaction happens at ingest, not at egress, whenever it can: content that was
/// never stored cannot leak from the store, and cannot be un-redacted by a later
/// bug in the egress policy.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RedactionPolicy {
    /// Run secret detection (keys, tokens, card numbers, national IDs).
    pub detect_secrets: bool,
    /// Regex patterns to strip, as raw strings compiled by the ingest crate.
    pub patterns: Vec<String>,
    /// Raise every memory from this source to at least this sensitivity.
    pub minimum_sensitivity: Option<Sensitivity>,
}

/// The outcome of one pull.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SyncReport {
    /// When the pull started.
    pub started_at: Timestamp,
    /// When it finished.
    pub finished_at: Timestamp,
    /// How many memories it produced.
    pub memories_ingested: u32,
    /// How many records were skipped as already seen.
    pub duplicates_skipped: u32,
    /// Failure description, if the pull failed. Never contains content.
    pub error: Option<String>,
}
