//! Construction of models, and the wrapper that makes the gate unavoidable.
//!
//! This module is the reason [`EgressPolicy`](crate::EgressPolicy) is not merely
//! advisory. The provider implementations are private to this crate, and the
//! only constructor that yields a remote model is [`remote`], which requires a
//! policy and a log. **A caller cannot obtain an ungated remote model**, because
//! no public function returns one (ARCHITECTURE §4.2).

use std::sync::Arc;

use async_trait::async_trait;

use crate::egress::{EgressLog, EgressPolicy};
use crate::model::{Completion, CompletionRequest, LanguageModel, ModelDescriptor};
use crate::schema::Schema;

/// Configuration for a local model.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalModelConfig {
    /// Model identifier as the runtime names it.
    pub model: String,
    /// Loopback endpoint of the local runtime.
    pub endpoint: String,
    /// Context window in tokens.
    pub context_tokens: u32,
}

/// Configuration for a remote model.
///
/// Carries no credential. Secrets are fetched from the keystore at construction
/// so an API key never sits in a `Debug`-printable configuration struct that
/// might reach a log or a crash report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteModelConfig {
    /// Which provider.
    pub provider: String,
    /// Model identifier.
    pub model: String,
    /// Tasks this provider is enabled for.
    ///
    /// An empty list means the provider is configured but permitted for nothing,
    /// which is the safe default when a user adds a provider before deciding
    /// what to use it for.
    pub enabled_tasks: Vec<crate::model::TaskKind>,
}

/// Builds a local model.
///
/// No gate: nothing leaves the device, so there is nothing to gate. Local
/// inference still carries its own risk — a compromised runtime sees `Secret`
/// content (THREAT_MODEL §T8) — but that is a supply-chain problem, not an
/// egress one.
///
/// # Errors
///
/// Returns [`Error::ProviderNotEnabled`](crate::Error::ProviderNotEnabled) if no
/// local provider feature is compiled in.
pub fn local(config: LocalModelConfig) -> crate::Result<Arc<dyn LanguageModel>> {
    todo!("construct the configured local provider behind its feature flag")
}

/// Builds a remote model, wrapped in its gate.
///
/// The only way to obtain a remote model. Note the return type: a concrete
/// [`GatedModel`], not a bare provider, and the providers themselves are private
/// to this crate.
///
/// # Errors
///
/// Returns [`Error::ProviderNotEnabled`](crate::Error::ProviderNotEnabled) if
/// the `remote` feature is off or the named provider is not compiled in.
pub fn remote(
    config: RemoteModelConfig,
    policy: Arc<dyn EgressPolicy>,
    log: Arc<dyn EgressLog>,
) -> crate::Result<GatedModel> {
    todo!("construct the provider behind its feature flag and wrap it in a GatedModel")
}

/// A remote model with its policy and audit log attached.
///
/// Every call evaluates the policy, applies the redaction plan, records the
/// decision, and only then transmits. The order matters: the log entry is
/// durable *before* the bytes move, so a crash mid-request cannot produce an
/// egress with no record of it.
pub struct GatedModel {
    inner: Arc<dyn LanguageModel>,
    policy: Arc<dyn EgressPolicy>,
    log: Arc<dyn EgressLog>,
}

impl core::fmt::Debug for GatedModel {
    /// Prints the descriptor and policy id, never configuration or credentials.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        todo!("print the model id and the policy id only")
    }
}

#[async_trait]
impl LanguageModel for GatedModel {
    fn descriptor(&self) -> ModelDescriptor {
        todo!("delegate to the wrapped provider")
    }

    async fn complete(&self, request: CompletionRequest) -> crate::Result<Completion> {
        todo!("evaluate policy, redact, record the log entry, then delegate")
    }

    async fn complete_with_schema(
        &self,
        request: CompletionRequest,
        schema: &Schema,
    ) -> crate::Result<String> {
        todo!("evaluate policy, redact, record the log entry, then delegate")
    }
}
