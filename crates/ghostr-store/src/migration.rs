//! Schema versioning.
//!
//! Migrations are written *before* the schema change that needs them, and a test
//! migrates a fixture database from every prior version (ROADMAP,
//! cross-cutting). This is stricter than most projects need because a chain
//! whose commitments were computed under one serialization and re-read under
//! another does not fail loudly — it fails as a verification error the user
//! cannot repair.

use serde::{Deserialize, Serialize};

/// The schema version this build writes.
pub const CURRENT_VERSION: u32 = 1;

/// One migration step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Migration {
    /// Version this migrates from.
    pub from: u32,
    /// Version this migrates to.
    pub to: u32,
    /// One-line description for the migration log.
    pub description: &'static str,
    /// Whether this rewrites hashed content.
    ///
    /// A migration that touches anything in a commitment preimage needs a chain
    /// re-verification pass afterwards, and needs to be flagged in the release
    /// notes as breaking even though it compiles (CLAUDE.md §7).
    pub touches_commitments: bool,
}

/// Every known migration, in order.
#[must_use]
pub fn migrations() -> &'static [Migration] {
    todo!("return the ordered migration list")
}

/// Reads the schema version recorded in a database.
///
/// # Errors
///
/// Returns [`Error::Backend`](crate::Error::Backend) if the version cannot be
/// read.
pub fn read_version(path: &std::path::Path) -> crate::Result<u32> {
    todo!("read the user_version pragma")
}

/// Applies every pending migration.
///
/// # Errors
///
/// Returns [`Error::SchemaTooNew`](crate::Error::SchemaTooNew) if the database
/// is newer than this build. Refusing is deliberate: a downgrade that writes
/// with an old understanding of the schema can corrupt a chain beyond repair.
pub fn migrate(path: &std::path::Path) -> crate::Result<MigrationReport> {
    todo!("apply pending migrations in one transaction each")
}

/// What a migration run did.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MigrationReport {
    /// Version before.
    pub from: u32,
    /// Version after.
    pub to: u32,
    /// Descriptions of what ran.
    pub applied: Vec<String>,
    /// Whether any step touched commitment preimages.
    pub commitments_touched: bool,
}
