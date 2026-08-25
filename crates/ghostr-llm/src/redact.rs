//! Redaction and pseudonymisation at the egress boundary.
//!
//! # What this achieves, and what it does not
//!
//! Pseudonymisation is **not** anonymisation. "Person A, seen daily, warm
//! valence, discussed a wedding" plus any outside knowledge re-identifies
//! quickly, and writing style alone is close to unique across enough text. This
//! layer raises the cost of casual correlation; it does not defeat a motivated
//! analyst, and the documentation should not imply otherwise
//! (THREAT_MODEL §T3).

use ghostr_core::ids::EntityId;
use ghostr_core::memory::Span;
use serde::{Deserialize, Serialize};

use crate::egress::SecretKind;

/// What will be changed before a payload is transmitted.
///
/// Produced by the policy, applied by the gate. Separating the two means a
/// decision can be logged and reviewed without having applied it, which is what
/// makes `--dry-run --remote` able to show a user exactly what *would* leave.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct RedactionPlan {
    /// Entity names to replace with pseudonyms.
    pub pseudonymise: Vec<PseudonymMapping>,
    /// Spans to remove entirely.
    pub strip: Vec<Span>,
    /// Whether the payload will be truncated to fit a context window.
    pub truncated: bool,
}

/// One name-to-pseudonym substitution.
///
/// Holds the pseudonym and the entity id — never the real name. The plan is
/// logged, and a plan containing real names would turn the audit log into a
/// second copy of the entity table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PseudonymMapping {
    /// Which entity.
    pub entity: EntityId,
    /// What it becomes, e.g. `Person A`.
    pub pseudonym: String,
    /// Where the name appears.
    pub spans: Vec<Span>,
}

/// Rewrites payloads according to a plan.
pub trait Redactor: Send + Sync {
    /// Builds a plan for `text`.
    ///
    /// # Errors
    ///
    /// Returns an error if entity resolution fails. Failure must propagate
    /// rather than degrade to "send it unredacted": a payload that should have
    /// carried a pseudonym and instead carries a real name is exactly the
    /// failure this layer exists to prevent.
    fn plan(&self, text: &str, entities: &[EntityId]) -> crate::Result<RedactionPlan>;

    /// Applies a plan.
    ///
    /// # Errors
    ///
    /// Returns an error if a span does not lie on a character boundary, which
    /// would corrupt the payload rather than redact it.
    fn apply(&self, text: &str, plan: &RedactionPlan) -> crate::Result<String>;
}

/// Finds credentials and identifiers in text.
///
/// Best-effort pattern matching, and it will miss things. It is a backstop for
/// content that should not have been stored, not a guarantee about what leaves.
pub trait SecretDetector: Send + Sync {
    /// Scans for secrets.
    ///
    /// Returns kinds and locations, never values.
    fn scan(&self, text: &str) -> Vec<SecretFinding>;
}

/// One detected secret.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SecretFinding {
    /// What kind.
    pub kind: SecretKind,
    /// Where.
    pub span: Span,
    /// How confident the detector is, in `0.0..=1.0`.
    ///
    /// Surfaced rather than thresholded internally: a low-confidence hit on an
    /// `nsec` is still worth showing a user.
    pub confidence: f32,
}
