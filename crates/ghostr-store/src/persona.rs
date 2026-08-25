//! [`PersonaStore`] — versioned persona models.

use async_trait::async_trait;
use ghostr_core::ids::PersonaVersion;
use ghostr_core::persona::{PersonaDelta, PersonaDiff, PersonaModel};
use ghostr_core::time::Timestamp;

/// Storage for persona versions and the deltas queued against them.
///
/// Old versions are never deleted. A quest issued under v12 is scored against
/// v12's claim, not v13's — otherwise a version bump would silently rewrite the
/// history of what the ghost believed when it was asked.
#[async_trait]
pub trait PersonaStore: Send + Sync {
    /// Writes a new version.
    ///
    /// # Errors
    ///
    /// Returns [`Error::AppendOnlyViolation`](crate::Error::AppendOnlyViolation)
    /// if the version exists.
    async fn put_version(&self, model: PersonaModel) -> crate::Result<()>;

    /// Reads one version.
    ///
    /// # Errors
    ///
    /// Returns an error if the read fails.
    async fn get_version(&self, version: PersonaVersion) -> crate::Result<Option<PersonaModel>>;

    /// The current version.
    ///
    /// # Errors
    ///
    /// Returns an error if the read fails.
    async fn head(&self) -> crate::Result<Option<PersonaModel>>;

    /// Every version, newest first, without their facets.
    ///
    /// Facets are large and a history listing does not need them.
    ///
    /// # Errors
    ///
    /// Returns an error if the read fails.
    async fn history(&self, limit: u32) -> crate::Result<Vec<PersonaVersionSummary>>;

    /// The stored diff between two versions, if one was computed.
    ///
    /// # Errors
    ///
    /// Returns an error if the read fails.
    async fn diff(
        &self,
        from: PersonaVersion,
        to: PersonaVersion,
    ) -> crate::Result<Option<PersonaDiff>>;

    /// Queues a correction for the next distillation.
    ///
    /// Implementations must reject deltas carrying `from_holdout: true`. Checking
    /// at the point of storage rather than at the point of use means a bug
    /// upstream fails loudly instead of quietly inflating the score (SPEC I7).
    ///
    /// # Errors
    ///
    /// Returns an error if the delta came from a held-out quest.
    async fn queue_delta(&self, delta: PersonaDelta) -> crate::Result<()>;

    /// Takes the queued deltas, clearing the queue.
    ///
    /// # Errors
    ///
    /// Returns an error if the read or clear fails.
    async fn drain_deltas(&self) -> crate::Result<Vec<PersonaDelta>>;
}

/// A persona version without its facets.
#[derive(Debug, Clone, PartialEq)]
pub struct PersonaVersionSummary {
    /// Which version.
    pub version: PersonaVersion,
    /// Its parent.
    pub parent: Option<PersonaVersion>,
    /// When it was distilled.
    pub created_at: Timestamp,
    /// How many changes its diff recorded.
    pub change_count: u32,
}
