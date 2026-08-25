//! [`EntityStore`] — the mapping between entity ids and real names.
//!
//! This table is the highest-value target in the store after the corpus itself:
//! it is what turns "Person A appears daily" into a name (THREAT_MODEL §T10,
//! asset A6). It is encrypted with everything else, and the mapping never
//! crosses the egress boundary — a remote model sees the pseudonym and nothing
//! behind it (SPEC §11.2).

use async_trait::async_trait;
use ghostr_core::ids::EntityId;
use ghostr_core::time::Timestamp;
use serde::{Deserialize, Serialize};

/// Storage for entities and their pseudonyms.
#[async_trait]
pub trait EntityStore: Send + Sync {
    /// Resolves a name to an entity, creating one if it is unknown.
    ///
    /// # Errors
    ///
    /// Returns an error if the write fails.
    async fn resolve_or_create(&self, name: &str, kind: EntityKind) -> crate::Result<Entity>;

    /// Reads an entity.
    ///
    /// # Errors
    ///
    /// Returns an error if the read fails.
    async fn get(&self, id: EntityId) -> crate::Result<Option<Entity>>;

    /// The stable pseudonym for an entity.
    ///
    /// Stable across calls and across sessions, so a remote model can follow
    /// "Person A" through a conversation without ever learning who that is. The
    /// mapping never leaves the device.
    ///
    /// # Errors
    ///
    /// Returns an error if the read fails.
    async fn pseudonym(&self, id: EntityId) -> crate::Result<String>;

    /// Merges `from` into `into`, repointing every reference.
    ///
    /// Entity resolution gets things wrong, and "Nan" and "Nan T." being two
    /// entities is the most common way. Merging is append-only at the memory
    /// level: memories are not rewritten, the alias is recorded.
    ///
    /// # Errors
    ///
    /// Returns an error if either entity is unknown.
    async fn merge(&self, from: EntityId, into: EntityId) -> crate::Result<()>;

    /// Every entity, for `gst forget` and for review.
    ///
    /// # Errors
    ///
    /// Returns an error if the read fails.
    async fn list(&self) -> crate::Result<Vec<Entity>>;
}

/// A person, place, or project.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Entity {
    /// Stable identifier.
    pub id: EntityId,
    /// Canonical name. Encrypted at rest; never egresses.
    pub name: String,
    /// Other names that resolve here.
    pub aliases: Vec<String>,
    /// What sort of thing this is.
    pub kind: EntityKind,
    /// Stable pseudonym used at the egress boundary.
    pub pseudonym: String,
    /// When first seen.
    pub first_seen: Timestamp,
    /// When last referenced.
    pub last_seen: Timestamp,
}

/// What sort of thing an entity is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum EntityKind {
    /// A person.
    Person,
    /// A place.
    Place,
    /// A project or piece of work.
    Project,
    /// An organisation.
    Organisation,
}
