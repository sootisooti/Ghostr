//! This crate's error type.
//!
//! Variants name rows, not contents (SPEC I8).

use ghostr_core::ids::MemoryId;

/// Result alias for this crate.
pub type Result<T, E = Error> = core::result::Result<T, E>;

/// Something went wrong reading or writing the store.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The keystore is locked, so nothing can be encrypted or decrypted.
    #[error("store is locked")]
    Locked,

    /// A row failed to decrypt.
    ///
    /// Under normal operation this means the database was tampered with or a row
    /// was moved between ids, since the AAD binds ciphertext to its row. It is
    /// worth surfacing loudly rather than skipping the row.
    #[error("row failed to decrypt: {table}")]
    RowDecryptFailed {
        /// Which table.
        table: &'static str,
    },

    /// An append-only table was asked to modify an existing row (SPEC I2).
    #[error("{table} is append-only; row already exists")]
    AppendOnlyViolation {
        /// Which table.
        table: &'static str,
    },

    /// A footage `seq` already exists.
    ///
    /// The last line of defence against a forked chain. Two devices sealing the
    /// same day is the failure this prevents, and it is enforced by a uniqueness
    /// constraint in the schema rather than a check in application code
    /// (SPEC Q10).
    #[error("footage seq {seq} is already sealed")]
    DuplicateSeq {
        /// The conflicting sequence number.
        seq: u64,
    },

    /// Sealing would leave a hole in the chain (SPEC I3).
    #[error("footage seq {got} does not follow the tip {expected}")]
    ChainGap {
        /// The `seq` that was expected next.
        expected: u64,
        /// The `seq` that was offered.
        got: u64,
    },

    /// A memory referenced by another record does not exist.
    #[error("memory {id:?} not found")]
    MemoryNotFound {
        /// The missing memory.
        id: MemoryId,
    },

    /// A shredded memory was read for its content (SPEC Q6).
    ///
    /// Distinct from "not found" on purpose: the record still exists and its
    /// leaf hash still verifies the chain. Only the content is gone.
    #[error("memory {id:?} has been shredded")]
    Shredded {
        /// The shredded memory.
        id: MemoryId,
    },

    /// The schema is newer than this build understands.
    ///
    /// Refuse rather than guess. A downgrade that writes with an old
    /// understanding of the schema can corrupt a chain that cannot be repaired.
    #[error("schema version {found} is newer than supported version {supported}")]
    SchemaTooNew {
        /// Version found in the database.
        found: u32,
        /// Newest version this build handles.
        supported: u32,
    },

    /// A vector's width is not the index's.
    ///
    /// Almost always a model change: mixing two vector spaces produces
    /// neighbours that are not neighbours, and doing it silently is the worst
    /// way for that to happen. The fix is a rebuild, not a coercion.
    #[error("vector has {found} dimensions, index expects {expected}")]
    VectorDimensionMismatch {
        /// The width offered.
        found: u32,
        /// The width the index was built with.
        expected: u32,
    },

    /// The underlying database failed.
    #[error("database error during {operation}")]
    Backend {
        /// Which operation, e.g. `"begin transaction"`.
        operation: &'static str,
    },

    /// Encryption or decryption failed.
    #[error("crypto error")]
    Crypto(#[from] ghostr_crypto::Error),
}
