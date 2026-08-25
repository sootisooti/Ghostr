//! Model providers.
//!
//! Private to this crate. Nothing outside `ghostr-llm` can name these types, so
//! nothing outside can construct an ungated remote model — the property that
//! makes [`EgressPolicy`](crate::EgressPolicy) structural rather than advisory
//! (ARCHITECTURE §4.2).
//!
//! Both providers are feature-gated, so a default build contains neither and
//! cannot reach a model at all.

#[cfg(feature = "local-ollama")]
pub(crate) mod ollama;

#[cfg(feature = "remote")]
pub(crate) mod anthropic;

#[cfg(feature = "remote")]
pub(crate) mod openai_compatible;
