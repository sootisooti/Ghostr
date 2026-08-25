//! Language model traits, prompt assembly, and the egress gate.
//!
//! This crate is the boundary that makes the privacy claim checkable. Two rules
//! define it:
//!
//! 1. **Every model call in the workspace goes through [`LanguageModel`] or
//!    [`Embedder`]** (SPEC I4). No other crate may open a connection to a
//!    provider.
//! 2. **Nothing reaches a remote provider without passing [`EgressPolicy`] and
//!    landing in [`EgressLog`]** (SPEC I5).
//!
//! # Why the gate is here and not at the call sites
//!
//! A rule enforced at call sites is a rule that gets forgotten at the next call
//! site. Instead, remote providers are constructed exclusively through
//! [`gate::remote`], which returns a [`gate::GatedModel`]; the provider types
//! themselves are private to this crate. **There is no way to obtain an ungated
//! remote model**, so a caller cannot forget to check the policy — the type
//! system will not produce the object it would need in order to.
//!
//! # The default is local
//!
//! [`ModelDescriptor::locality`] lets a caller ask "may I send `Secret` content
//! here?" without knowing anything about providers. The default build has no
//! provider features enabled at all, which means a default build cannot egress.
//!
//! # Status
//!
//! Scaffold. Types and signatures are defined; bodies are [`todo!`].

#![forbid(unsafe_code)]
// CLAUDE.md §5 denies unwrap/expect/panic in library code, and names tests as
// the exception: a failed assertion should panic loudly with a message, and
// threading `Result` through test bodies buries what is actually being asserted.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]
// SCAFFOLD: every function body in this crate is `todo!()`. These allows exist
// only for the scaffold phase and are removed crate-by-crate as bodies land.
// `unused_variables` and `dead_code` fire because a diverging body never reads
// its arguments and never calls its helpers; parameters keep real names rather
// than `_` prefixes so the signatures stay readable. `clippy::todo` is denied
// workspace-wide by CLAUDE.md §5 and this is the documented exception.
// `cargo xtask scaffold-status` counts these markers so they cannot be quietly
// forgotten.
#![allow(unused_variables, dead_code, clippy::todo)]

pub mod egress;
pub mod embed;
pub mod error;
pub mod gate;
pub mod model;
pub mod policy;
pub mod prompt;
pub mod redact;
pub mod schema;

pub use egress::{EgressDecision, EgressEntry, EgressLog, EgressPolicy, EgressRequest};
pub use embed::{EmbedInput, Embedder, EmbedderDescriptor, Embedding};
pub use error::{Error, Result};
pub use model::{
    Completion, CompletionRequest, LanguageModel, LanguageModelExt, Locality, ModelDescriptor,
};
pub use policy::StandardPolicy;
pub use schema::{Schema, StructuredOutput};
