//! Schema-constrained output.
//!
//! [`StructuredOutput`] is defined here rather than taken from `schemars`,
//! keeping a derive-macro dependency out of the tree until something needs it.
//! Schemas are written by hand for now, which is bearable because there are few
//! of them and each one is a security boundary worth reading (THREAT_MODEL §T7).

use serde::de::DeserializeOwned;

/// A JSON Schema constraining a model's output.
#[derive(Debug, Clone, PartialEq)]
pub struct Schema {
    /// A stable name, used in prompts and snapshot tests.
    pub name: &'static str,
    /// The schema document.
    pub json: serde_json::Value,
}

impl Schema {
    /// Validates a JSON value against this schema.
    ///
    /// # Errors
    ///
    /// Returns [`Error::SchemaViolation`](crate::Error::SchemaViolation) if the
    /// value does not conform.
    pub fn validate(&self, value: &serde_json::Value) -> crate::Result<()> {
        todo!("validate the value against the schema document")
    }
}

/// A type a model can be constrained to produce.
///
/// Implementations are the extraction path's contract with the model. Keep them
/// tight: every optional field and every free-string field is somewhere an
/// injected instruction can survive validation and reach the persona model.
pub trait StructuredOutput: DeserializeOwned + Send + Sync {
    /// The schema for this type.
    fn schema() -> Schema;
}
