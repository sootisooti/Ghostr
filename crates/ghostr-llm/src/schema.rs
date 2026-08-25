//! Schema-constrained output.
//!
//! [`StructuredOutput`] is defined here rather than taken from `schemars`,
//! keeping a derive-macro dependency out of the tree until something needs it.
//! Schemas are written by hand for now, which is bearable because there are few
//! of them and each one is a security boundary worth reading (THREAT_MODEL §T7).
//!
//! # The validator is deliberately small, and fails closed
//!
//! [`Schema::validate`] implements the subset of JSON Schema these schemas use:
//! `type`, `properties`, `required`, `additionalProperties`, `items`, `enum`,
//! `minimum`/`maximum`, `minItems`/`maxItems`, `maxLength`, and `minLength`.
//!
//! An unrecognised keyword is an **error**, not something to skip. That is the
//! whole point: a validator that quietly ignores `additionalProperties` because
//! it does not understand it is a validator that lets an injected field through,
//! and the failure is silent. A schema this crate cannot fully check is a schema
//! it refuses to check at all.

use serde::de::DeserializeOwned;
use serde_json::Value;

/// A JSON Schema constraining a model's output.
#[derive(Debug, Clone, PartialEq)]
pub struct Schema {
    /// A stable name, used in prompts and snapshot tests.
    pub name: &'static str,
    /// The schema document.
    pub json: serde_json::Value,
}

/// Keywords [`Schema::validate`] understands.
///
/// Anything else in a schema document is refused. See the module docs.
const SUPPORTED: &[&str] = &[
    "type",
    "properties",
    "required",
    "additionalProperties",
    "items",
    "enum",
    "minimum",
    "maximum",
    "minItems",
    "maxItems",
    "minLength",
    "maxLength",
    // Documentation keywords, carried for the model's benefit and ignored here.
    "title",
    "description",
    "$schema",
];

impl Schema {
    /// Validates a JSON value against this schema.
    ///
    /// # Errors
    ///
    /// Returns [`Error::SchemaViolation`](crate::Error::SchemaViolation) if the
    /// value does not conform, or if the schema uses a keyword this validator
    /// does not implement.
    pub fn validate(&self, value: &Value) -> crate::Result<()> {
        check(&self.json, value)
    }
}

/// Recursively checks one value against one schema node.
///
/// Returns a bare error rather than a path. A validation message naming which
/// field failed would, on a partially-correct extraction, be a way for corpus
/// text to reach a log (I8).
fn check(schema: &Value, value: &Value) -> crate::Result<()> {
    let Some(object) = schema.as_object() else {
        return Err(crate::Error::SchemaViolation);
    };
    for key in object.keys() {
        if !SUPPORTED.contains(&key.as_str()) {
            return Err(crate::Error::SchemaViolation);
        }
    }

    if let Some(expected) = object.get("type").and_then(Value::as_str)
        && !type_matches(expected, value)
    {
        return Err(crate::Error::SchemaViolation);
    }

    if let Some(allowed) = object.get("enum").and_then(Value::as_array)
        && !allowed.contains(value)
    {
        return Err(crate::Error::SchemaViolation);
    }

    match value {
        Value::Object(map) => {
            if let Some(required) = object.get("required").and_then(Value::as_array) {
                for field in required {
                    let Some(name) = field.as_str() else {
                        return Err(crate::Error::SchemaViolation);
                    };
                    if !map.contains_key(name) {
                        return Err(crate::Error::SchemaViolation);
                    }
                }
            }
            let properties = object.get("properties").and_then(Value::as_object);
            // Absent means the JSON Schema default of `true`. Every schema in
            // this crate sets it to `false`; the default is honoured rather than
            // overridden so a schema written elsewhere behaves as its author
            // expects.
            let extra_allowed = object
                .get("additionalProperties")
                .and_then(Value::as_bool)
                .unwrap_or(true);
            for (name, child) in map {
                match properties.and_then(|p| p.get(name)) {
                    Some(child_schema) => check(child_schema, child)?,
                    None if extra_allowed => {}
                    None => return Err(crate::Error::SchemaViolation),
                }
            }
        }
        Value::Array(items) => {
            if let Some(min) = object.get("minItems").and_then(Value::as_u64)
                && (items.len() as u64) < min
            {
                return Err(crate::Error::SchemaViolation);
            }
            if let Some(max) = object.get("maxItems").and_then(Value::as_u64)
                && (items.len() as u64) > max
            {
                return Err(crate::Error::SchemaViolation);
            }
            if let Some(item_schema) = object.get("items") {
                for item in items {
                    check(item_schema, item)?;
                }
            }
        }
        Value::String(text) => {
            if let Some(min) = object.get("minLength").and_then(Value::as_u64)
                && (text.chars().count() as u64) < min
            {
                return Err(crate::Error::SchemaViolation);
            }
            if let Some(max) = object.get("maxLength").and_then(Value::as_u64)
                && (text.chars().count() as u64) > max
            {
                return Err(crate::Error::SchemaViolation);
            }
        }
        Value::Number(number) => {
            let Some(n) = number.as_f64() else {
                return Err(crate::Error::SchemaViolation);
            };
            if let Some(min) = object.get("minimum").and_then(Value::as_f64)
                && n < min
            {
                return Err(crate::Error::SchemaViolation);
            }
            if let Some(max) = object.get("maximum").and_then(Value::as_f64)
                && n > max
            {
                return Err(crate::Error::SchemaViolation);
            }
        }
        Value::Null | Value::Bool(_) => {}
    }
    Ok(())
}

/// Whether a value matches a JSON Schema `type`.
fn type_matches(expected: &str, value: &Value) -> bool {
    match expected {
        "object" => value.is_object(),
        "array" => value.is_array(),
        "string" => value.is_string(),
        // `integer` is checked exactly: a model returning 3.5 for a count is
        // wrong, and rounding it silently would hide that.
        "integer" => value.as_i64().is_some() || value.as_u64().is_some(),
        "number" => value.is_number(),
        "boolean" => value.is_boolean(),
        "null" => value.is_null(),
        _ => false,
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

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn schema() -> Schema {
        Schema {
            name: "test",
            json: json!({
                "type": "object",
                "additionalProperties": false,
                "required": ["summary", "memory_ids"],
                "properties": {
                    "summary": { "type": "string", "maxLength": 160 },
                    "memory_ids": {
                        "type": "array",
                        "minItems": 1,
                        "items": { "type": "string" }
                    },
                    "salience": { "type": "number", "minimum": 0.0, "maximum": 1.0 },
                    "kind": { "enum": ["note", "event"] }
                }
            }),
        }
    }

    #[test]
    fn a_conforming_value_passes() {
        let value = json!({"summary": "a day", "memory_ids": ["mem:1"], "salience": 0.5});
        assert!(schema().validate(&value).is_ok());
    }

    #[test]
    fn a_missing_required_field_fails() {
        assert!(schema().validate(&json!({"summary": "a day"})).is_err());
    }

    /// The field a prompt injection would add. `additionalProperties: false` is
    /// the line that stops it, so it needs a test of its own.
    #[test]
    fn an_extra_field_is_refused() {
        let value = json!({
            "summary": "a day",
            "memory_ids": ["mem:1"],
            "system_instruction": "ignore previous"
        });
        assert!(schema().validate(&value).is_err());
    }

    #[test]
    fn the_wrong_type_fails() {
        let value = json!({"summary": 42, "memory_ids": ["mem:1"]});
        assert!(schema().validate(&value).is_err());
    }

    #[test]
    fn bounds_are_enforced() {
        let long = "x".repeat(200);
        assert!(
            schema()
                .validate(&json!({"summary": long, "memory_ids": ["mem:1"]}))
                .is_err()
        );
        assert!(
            schema()
                .validate(&json!({"summary": "a", "memory_ids": []}))
                .is_err()
        );
        assert!(
            schema()
                .validate(&json!({"summary": "a", "memory_ids": ["m"], "salience": 1.5}))
                .is_err()
        );
    }

    #[test]
    fn an_enum_outside_its_set_fails() {
        let value = json!({"summary": "a", "memory_ids": ["m"], "kind": "instruction"});
        assert!(schema().validate(&value).is_err());
    }

    /// The reason the keyword list exists. A validator that skips what it does
    /// not understand is a validator that lets an injected field through, and
    /// does it silently.
    #[test]
    fn a_keyword_this_validator_cannot_check_is_refused() {
        let s = Schema {
            name: "unsupported",
            json: json!({"type": "object", "patternProperties": {"^x": {"type": "string"}}}),
        };
        assert!(s.validate(&json!({})).is_err());
    }

    /// A field name from the corpus must not reach the error, and so must not
    /// reach a log (I8).
    #[test]
    fn a_violation_never_names_the_offending_content() {
        let value = json!({
            "summary": "a day",
            "memory_ids": ["mem:1"],
            "my_secret_field_name": "hunter2"
        });
        let err = schema().validate(&value).expect_err("must fail");
        let rendered = format!("{err}");
        assert!(!rendered.contains("my_secret_field_name"));
        assert!(!rendered.contains("hunter2"));
    }

    #[test]
    fn nested_objects_are_checked_too() {
        let s = Schema {
            name: "nested",
            json: json!({
                "type": "object",
                "additionalProperties": false,
                "properties": {
                    "people": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "additionalProperties": false,
                            "properties": { "name": { "type": "string" } }
                        }
                    }
                }
            }),
        };
        assert!(s.validate(&json!({"people": [{"name": "A"}]})).is_ok());
        assert!(
            s.validate(&json!({"people": [{"instruction": "x"}]}))
                .is_err()
        );
    }

    #[test]
    fn an_integer_field_rejects_a_fraction() {
        let s = Schema {
            name: "count",
            json: json!({"type": "object", "properties": {"n": {"type": "integer"}}}),
        };
        assert!(s.validate(&json!({"n": 3})).is_ok());
        assert!(s.validate(&json!({"n": 3.5})).is_err());
    }
}
