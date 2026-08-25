//! The error type for this crate.
//!
//! Errors carry identifiers and context, never content: no variant may hold a
//! memory body, a persona facet, an entity name, or key material (SPEC I8).
//! When you need to say *which* memory failed, hold its
//! [`MemoryId`](crate::ids::MemoryId).

use crate::ids::MemoryId;

/// Result alias for this crate.
pub type Result<T, E = Error> = core::result::Result<T, E>;

/// Something went wrong in a pure domain operation.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// Canonical encoding failed, or decoding hit bytes that are not canonical.
    ///
    /// Non-canonical input is rejected rather than normalised: accepting two
    /// encodings of the same value would let two different byte strings produce
    /// two different commitments for one memory.
    #[error("canonical encoding is invalid: {reason}")]
    Canonical {
        /// What was wrong with the encoding. Describes structure, never content.
        reason: &'static str,
    },

    /// A hash did not match the value it was supposed to commit to.
    #[error("commitment mismatch at {context}")]
    CommitmentMismatch {
        /// Where the mismatch was found, e.g. `"footage.link"`.
        context: &'static str,
    },

    /// A Merkle inclusion proof did not verify against its root.
    #[error("merkle proof does not verify (depth {depth})")]
    InvalidProof {
        /// Depth of the supplied path, for triage.
        depth: usize,
    },

    /// A field carried a value outside its documented range, e.g. a salience
    /// outside `0.0..=1.0`.
    #[error("field `{field}` is out of range")]
    OutOfRange {
        /// The offending field's name.
        field: &'static str,
    },

    /// A footage referenced a memory that is not in the window it seals.
    #[error("memory {id:?} is not in the sealed window")]
    MemoryOutOfWindow {
        /// The offending memory.
        id: MemoryId,
    },

    /// A sealed record was asked to change (SPEC I2).
    #[error("record is sealed and cannot be modified: {what}")]
    Sealed {
        /// Which record, e.g. `"footage"`.
        what: &'static str,
    },
}
