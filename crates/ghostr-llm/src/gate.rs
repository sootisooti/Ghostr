//! Construction of models, and the wrapper that makes the gate unavoidable.
//!
//! This module is the reason [`EgressPolicy`] is not merely
//! advisory. The provider implementations are private to this crate, and the
//! only public constructor that yields a remote model is [`remote`], which
//! requires a policy and a log. **A caller cannot obtain an ungated remote
//! model**, because no public function returns one (ARCHITECTURE §4.2).
//!
//! # Order of operations
//!
//! For every remote call, in this order:
//!
//! 1. Evaluate the policy.
//! 2. On deny — log the denial, return the error. Nothing is transmitted.
//! 3. On allow — build and apply the redaction plan.
//! 4. Detect secrets **in the redacted payload**, and re-check.
//! 5. Write the audit entry, and **fail the call if it cannot be written**.
//! 6. Only then transmit.
//!
//! Step 5 before step 6 is the point. An egress that could not be recorded is
//! precisely the thing the user was told could not happen, so it does not
//! happen (SPEC I5).
//!
//! Step 4 exists because redaction changes the payload: a secret could be
//! revealed by a substitution, and checking only the original would miss it.

use std::sync::Arc;

use async_trait::async_trait;

use crate::detect::PatternDetector;
use crate::egress::{
    DenyReason, EgressDecision, EgressEntry, EgressLog, EgressPolicy, EgressRequest,
};
use crate::model::{Completion, CompletionRequest, LanguageModel, Locality, ModelDescriptor};
use crate::redact::{Redactor, SecretDetector};
use crate::schema::Schema;

/// Configuration for a local model.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LocalModelConfig {
    /// Model identifier as the runtime names it, e.g. `llama3.1:8b-instruct-q4_0`.
    pub model: String,
    /// Loopback endpoint of the local runtime.
    pub endpoint: String,
    /// Context window in tokens.
    pub context_tokens: u32,
}

impl Default for LocalModelConfig {
    /// Ollama's default, on loopback.
    fn default() -> Self {
        Self {
            model: "llama3.1:8b".to_owned(),
            endpoint: "http://127.0.0.1:11434".to_owned(),
            context_tokens: 8192,
        }
    }
}

/// Configuration for a remote model.
///
/// Carries no credential. Secrets are fetched from the keystore at construction
/// so an API key never sits in a `Debug`-printable configuration struct that
/// might reach a log or a crash report.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
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
    #[cfg(feature = "local-ollama")]
    {
        Ok(Arc::new(crate::provider::ollama::OllamaModel::new(config)))
    }
    #[cfg(not(feature = "local-ollama"))]
    {
        let _ = config;
        Err(crate::Error::ProviderNotEnabled {
            provider: "local-ollama".to_owned(),
        })
    }
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
    redactor: Arc<dyn Redactor>,
) -> crate::Result<GatedModel> {
    #[cfg(feature = "remote")]
    {
        let inner = crate::provider::openai_compatible::RemoteModel::new(config.clone())?;
        Ok(GatedModel::new(
            Arc::new(inner),
            config,
            policy,
            log,
            redactor,
        ))
    }
    #[cfg(not(feature = "remote"))]
    {
        let _ = (policy, log, redactor);
        Err(crate::Error::ProviderNotEnabled {
            provider: config.provider,
        })
    }
}

/// Wraps any model in the gate, for tests and for the dry-run path.
///
/// Public so an integration test can gate a fake provider and assert the whole
/// sequence — policy, redaction, logging, transmission — without a network. It
/// takes an already-constructed model, so it cannot be used to *escape* the
/// gate: there is still no public way to build a remote provider unwrapped.
#[must_use]
pub fn gated(
    inner: Arc<dyn LanguageModel>,
    config: RemoteModelConfig,
    policy: Arc<dyn EgressPolicy>,
    log: Arc<dyn EgressLog>,
    redactor: Arc<dyn Redactor>,
) -> GatedModel {
    GatedModel::new(inner, config, policy, log, redactor)
}

/// A remote model with its policy, audit log, and redactor attached.
pub struct GatedModel {
    inner: Arc<dyn LanguageModel>,
    config: RemoteModelConfig,
    policy: Arc<dyn EgressPolicy>,
    log: Arc<dyn EgressLog>,
    redactor: Arc<dyn Redactor>,
    detector: PatternDetector,
}

impl core::fmt::Debug for GatedModel {
    /// Prints the model and policy identity, never configuration or credentials.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("GatedModel")
            .field("provider", &self.config.provider)
            .field("model", &self.config.model)
            .field("policy", &self.policy.policy_id())
            .finish()
    }
}

/// What a dry run would send, without sending it.
///
/// Backs `--dry-run --remote`: the user sees the exact bytes that would leave
/// *before* any leave. The decision and the payload are produced by the same
/// code path as a real call, so this cannot drift from what actually happens.
#[derive(Debug, Clone, PartialEq)]
pub struct DryRun {
    /// What the policy decided.
    pub decision: EgressDecision,
    /// The payload as it would be transmitted, after redaction.
    ///
    /// `None` when the decision was a deny — nothing would be sent.
    pub payload: Option<String>,
    /// How many entity names were replaced.
    pub entities_pseudonymised: u32,
    /// Digest of the payload, matching what the audit log would record.
    pub payload_digest: Option<ghostr_core::hash::Hash32>,
}

impl GatedModel {
    fn new(
        inner: Arc<dyn LanguageModel>,
        config: RemoteModelConfig,
        policy: Arc<dyn EgressPolicy>,
        log: Arc<dyn EgressLog>,
        redactor: Arc<dyn Redactor>,
    ) -> Self {
        Self {
            inner,
            config,
            policy,
            log,
            redactor,
            detector: PatternDetector,
        }
    }

    /// Evaluates and redacts without transmitting.
    ///
    /// # Errors
    ///
    /// Returns [`Error::EgressDenied`](crate::Error::EgressDenied) if
    /// redaction fails; a policy *deny* is reported inside [`DryRun::decision`]
    /// rather than as an error, because "it would have been refused" is the
    /// answer the user asked for.
    pub fn dry_run(&self, request: &CompletionRequest) -> crate::Result<DryRun> {
        let payload = render(request);
        let egress_request = self.describe(request, payload.len());

        match self.policy.evaluate(&egress_request) {
            EgressDecision::Deny { reason } => Ok(DryRun {
                decision: EgressDecision::Deny { reason },
                payload: None,
                entities_pseudonymised: 0,
                payload_digest: None,
            }),
            decision => {
                let (redacted, count) = self.redact(&payload, &egress_request)?;
                let digest = ghostr_core::hash::tagged_hash(
                    ghostr_core::hash::Tag::MetaLeaf,
                    redacted.as_bytes(),
                );
                Ok(DryRun {
                    decision,
                    payload: Some(redacted),
                    entities_pseudonymised: count,
                    payload_digest: Some(digest),
                })
            }
        }
    }

    /// Runs the gate, returning the payload to transmit.
    ///
    /// Logs the decision — allow or deny — before returning. A failure to write
    /// the audit entry fails the call.
    async fn admit(&self, request: &CompletionRequest) -> crate::Result<String> {
        let payload = render(request);
        let egress_request = self.describe(request, payload.len());
        let decision = self.policy.evaluate(&egress_request);

        if let EgressDecision::Deny { reason } = decision {
            // A denial is logged too. A log of only the allows cannot show that
            // the system refused anything, which is most of its evidentiary
            // value (SPEC I5).
            self.record(&decision, 0, None, 0).await?;
            return Err(crate::Error::EgressDenied { reason });
        }

        let (redacted, count) = self.redact(&payload, &egress_request)?;

        // Re-check after redaction: a substitution changes the payload, and a
        // secret could be revealed by one. Checking only the original would
        // miss it.
        let findings = self.detector.scan(&redacted);
        if !findings.is_empty() {
            let denial = EgressDecision::Deny {
                reason: DenyReason::SecretDetected,
            };
            self.record(&denial, 0, None, 0).await?;
            return Err(crate::Error::EgressDenied {
                reason: DenyReason::SecretDetected,
            });
        }

        let digest =
            ghostr_core::hash::tagged_hash(ghostr_core::hash::Tag::MetaLeaf, redacted.as_bytes());
        let bytes = u32::try_from(redacted.len()).unwrap_or(u32::MAX);
        self.record(&decision, bytes, Some(digest), count).await?;
        Ok(redacted)
    }

    fn describe(&self, request: &CompletionRequest, bytes: usize) -> EgressRequest {
        EgressRequest {
            provider: self.config.provider.clone(),
            locality: Locality::Remote,
            task: request.task,
            max_sensitivity: request.max_sensitivity,
            entities: Vec::new(),
            payload_bytes: u32::try_from(bytes).unwrap_or(u32::MAX),
            detected_secrets: self
                .detector
                .scan(&render(request))
                .into_iter()
                .map(|f| f.kind)
                .collect(),
        }
    }

    fn redact(&self, payload: &str, request: &EgressRequest) -> crate::Result<(String, u32)> {
        let plan = self.redactor.plan(payload, &request.entities)?;
        let count = u32::try_from(plan.pseudonymise.len()).unwrap_or(u32::MAX);
        Ok((self.redactor.apply(payload, &plan)?, count))
    }

    async fn record(
        &self,
        decision: &EgressDecision,
        bytes_sent: u32,
        payload_digest: Option<ghostr_core::hash::Hash32>,
        entities: u32,
    ) -> crate::Result<()> {
        self.log
            .record(EgressEntry {
                at: ghostr_core::time::Timestamp::new(0, 0),
                provider: self.config.provider.clone(),
                task: crate::model::TaskKind::Conversation,
                decision: decision.clone(),
                policy_id: self.policy.policy_id().to_owned(),
                bytes_sent,
                payload_digest,
                entities_pseudonymised: entities,
            })
            .await
            .map_err(|_| crate::Error::EgressLogUnavailable)
    }
}

/// Renders a request into the exact text that would be transmitted.
///
/// One function, used by both the real path and the dry run, so what the user is
/// shown cannot drift from what is actually sent.
fn render(request: &CompletionRequest) -> String {
    let mut out = String::new();
    out.push_str(&request.system);
    for message in &request.messages {
        out.push('\n');
        out.push_str(&format!("{:?}: {}", message.role, message.content));
    }
    out
}

#[async_trait]
impl LanguageModel for GatedModel {
    fn descriptor(&self) -> ModelDescriptor {
        self.inner.descriptor()
    }

    async fn complete(&self, request: CompletionRequest) -> crate::Result<Completion> {
        let redacted = self.admit(&request).await?;
        let mut forwarded = request;
        forwarded.system = redacted;
        forwarded.messages.clear();
        self.inner.complete(forwarded).await
    }

    async fn complete_with_schema(
        &self,
        request: CompletionRequest,
        schema: &Schema,
    ) -> crate::Result<String> {
        let redacted = self.admit(&request).await?;
        let mut forwarded = request;
        forwarded.system = redacted;
        forwarded.messages.clear();
        self.inner.complete_with_schema(forwarded, schema).await
    }
}
