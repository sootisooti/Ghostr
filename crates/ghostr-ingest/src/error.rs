//! This crate's error type.

use ghostr_core::ids::SourceId;

/// Result alias for this crate.
pub type Result<T, E = Error> = core::result::Result<T, E>;

/// Something went wrong pulling from a source.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// No adapter is compiled in for this source kind.
    #[error("no adapter for source kind `{kind}` in this build")]
    NoAdapter {
        /// The source kind that was configured.
        kind: String,
    },

    /// The source could not be reached or read.
    #[error("source {id:?} unreachable")]
    Unreachable {
        /// Which source.
        id: SourceId,
    },

    /// The source returned data the adapter could not parse.
    ///
    /// Carries a location, never the content that failed. An unparseable record
    /// is often exactly the record you would least like copied into a log.
    #[error("source {id:?} returned unparseable data at {location}")]
    Unparseable {
        /// Which source.
        id: SourceId,
        /// Where in the source, e.g. a file path and line.
        location: String,
    },

    /// The cursor does not belong to this source kind.
    ///
    /// Refusing is deliberate: proceeding from an unrecognised cursor would
    /// re-ingest from the beginning or silently skip a span, and both are worse
    /// than stopping.
    #[error("cursor is not valid for source {id:?}")]
    InvalidCursor {
        /// Which source.
        id: SourceId,
    },

    /// The store rejected the batch.
    #[error("store error")]
    Store(#[from] ghostr_store::Error),
}
