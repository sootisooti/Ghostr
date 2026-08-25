//! [`FootageStore`] — sealed daily records and the commitment chain.

use async_trait::async_trait;
use ghostr_core::footage::{ChainTip, Footage};

/// Storage for sealed footage.
///
/// The only mutating operation is [`FootageStore::seal`], and it fails rather
/// than overwrites. Immutability here is not a convention the application
/// upholds — it is a uniqueness constraint in the schema, because the
/// application is exactly what might be wrong (SPEC I2, I3).
#[async_trait]
pub trait FootageStore: Send + Sync {
    /// Seals a footage, making it immutable.
    ///
    /// Must be a single transaction. A partial seal leaves a chain that cannot
    /// be repaired — there is no valid state between "not sealed" and "sealed",
    /// and a half-written link is indistinguishable from a tampered one.
    ///
    /// # Errors
    ///
    /// Returns [`Error::DuplicateSeq`](crate::Error::DuplicateSeq) if the `seq`
    /// exists — the fork guard — or
    /// [`Error::ChainGap`](crate::Error::ChainGap) if it does not directly
    /// follow the tip.
    async fn seal(&self, footage: Footage) -> crate::Result<()>;

    /// Reads one sealed footage.
    ///
    /// # Errors
    ///
    /// Returns an error if the read fails.
    async fn get(&self, seq: u64) -> crate::Result<Option<Footage>>;

    /// Reads a range of footage, inclusive of both ends.
    ///
    /// # Errors
    ///
    /// Returns an error if the read fails.
    async fn range(&self, from_seq: u64, to_seq: u64) -> crate::Result<Vec<Footage>>;

    /// The head of the chain, or `None` before the first seal.
    ///
    /// # Errors
    ///
    /// Returns an error if the read fails.
    async fn tip(&self) -> crate::Result<Option<ChainTip>>;

    /// The most recent `seq` whose local date is on or before `date`.
    ///
    /// Days are addressed by `seq`, not by date, because `seq` is what the chain
    /// commits to and what stays gapless when the wall clock does something
    /// strange (SPEC Q11).
    ///
    /// # Errors
    ///
    /// Returns an error if the read fails.
    async fn seq_for_date(&self, date: chrono::NaiveDate) -> crate::Result<Option<u64>>;
}
