//! [`LanguageModel`] — the trait every model call in the workspace goes through.

use async_trait::async_trait;
use ghostr_core::sensitivity::Sensitivity;
use serde::{Deserialize, Serialize};

use crate::schema::{Schema, StructuredOutput};

/// A language model.
///
/// Object-safe on purpose: the composition root hands out
/// `Arc<dyn LanguageModel>` and callers cannot tell a local model from a gated
/// remote one, which is what makes the two substitutable.
///
/// Typed structured output lives in [`LanguageModelExt`] rather than here,
/// because a generic method would make this trait non-object-safe.
#[async_trait]
pub trait LanguageModel: Send + Sync {
    /// What this model is and where it runs.
    fn descriptor(&self) -> ModelDescriptor;

    /// Free-form completion.
    ///
    /// # Errors
    ///
    /// Returns [`Error::EgressDenied`](crate::Error::EgressDenied) if the gate
    /// refused, or [`Error::Transport`](crate::Error::Transport) if the model
    /// could not be reached.
    async fn complete(&self, request: CompletionRequest) -> crate::Result<Completion>;

    /// Schema-constrained completion returning raw JSON text.
    ///
    /// The untyped half of structured output. Prefer
    /// [`LanguageModelExt::complete_structured`], which validates and
    /// deserializes; this exists so the trait stays object-safe.
    ///
    /// # Errors
    ///
    /// Returns [`Error::SchemaViolation`](crate::Error::SchemaViolation) if the
    /// model would not produce conforming output.
    async fn complete_with_schema(
        &self,
        request: CompletionRequest,
        schema: &Schema,
    ) -> crate::Result<String>;
}

/// Typed structured output, blanket-implemented for every [`LanguageModel`].
///
/// Split out because `async fn f<T>(..)` in a trait makes that trait
/// non-object-safe, and the composition root needs `dyn LanguageModel`. The
/// extension trait gives back the typed ergonomics without costing dynamic
/// dispatch at the seam.
#[async_trait]
pub trait LanguageModelExt: LanguageModel {
    /// Completes into `T`, validating against `T`'s schema.
    ///
    /// The **only** call the extraction path may use. Free-form prose from a
    /// model that has just been fed third-party text is untrusted output from an
    /// untrusted input; constraining it to a schema means anything that does not
    /// parse is discarded rather than interpreted (THREAT_MODEL §T7).
    ///
    /// # Errors
    ///
    /// Returns [`Error::SchemaViolation`](crate::Error::SchemaViolation) if the
    /// output does not validate or deserialize.
    async fn complete_structured<T>(&self, request: CompletionRequest) -> crate::Result<T>
    where
        T: StructuredOutput + 'static;
}

#[async_trait]
impl<M: LanguageModel + ?Sized> LanguageModelExt for M {
    async fn complete_structured<T>(&self, request: CompletionRequest) -> crate::Result<T>
    where
        T: StructuredOutput + 'static,
    {
        let schema = T::schema();
        let raw = self.complete_with_schema(request, &schema).await?;
        // Parse, validate, then deserialize — in that order. Deserializing first
        // would let serde's own leniency (unknown fields, coercions) decide what
        // conforms, and the schema is the contract, not serde.
        let value: serde_json::Value =
            serde_json::from_str(&raw).map_err(|_| crate::Error::SchemaViolation)?;
        schema.validate(&value)?;
        serde_json::from_value(value).map_err(|_| crate::Error::SchemaViolation)
    }
}

/// What a model is, and — crucially — where it runs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelDescriptor {
    /// Provider-qualified identifier, e.g. `ollama:llama3.1:8b-q4`.
    pub id: String,
    /// Whether inference happens on this device.
    pub locality: Locality,
    /// Context window in tokens.
    pub context_tokens: u32,
    /// Rough capability tier, used to pick which quest kinds to attempt.
    pub tier: CapabilityTier,
    /// Whether this model can constrain output to a schema natively.
    ///
    /// When `false`, structured output is emulated by prompting and validating,
    /// which fails more often and must retry rather than accept loose output.
    pub native_schema: bool,
}

impl ModelDescriptor {
    /// Whether content at `sensitivity` may be sent to this model.
    ///
    /// A necessary condition, never a sufficient one: the egress policy still
    /// evaluates provider configuration, redaction, and secret detection. This
    /// exists so a caller can route sensibly *before* building a prompt it is
    /// not allowed to send.
    #[must_use]
    pub fn accepts(&self, sensitivity: Sensitivity) -> bool {
        match self.locality {
            Locality::Local => true,
            Locality::Remote => sensitivity.may_egress(),
        }
    }
}

/// Where inference happens.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Locality {
    /// On this device. Sees everything, including `Secret`.
    ///
    /// Not risk-free: a compromised local inference binary is a total corpus
    /// compromise, and model runtimes rarely get the scrutiny crypto libraries
    /// do (THREAT_MODEL §T8).
    Local,
    /// Somewhere else. Subject to the egress gate without exception.
    Remote,
}

/// Roughly what a model can be trusted to do well.
///
/// Drives graceful degradation: when the local model cannot clear the bar for
/// `VoiceProbe`, the right response is fewer quests of the mechanical kinds, not
/// bad quests of the hard ones (SPEC Q7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum CapabilityTier {
    /// Extraction and classification only.
    Small,
    /// The supported floor: an ~8B-class quantized local model.
    Baseline,
    /// Comfortably handles voice and counterfactual generation.
    Strong,
}

/// A request to a model.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CompletionRequest {
    /// The instruction channel. Authored by Ghostr, never by corpus content.
    pub system: String,
    /// The conversation.
    pub messages: Vec<Message>,
    /// Highest sensitivity of anything in this request.
    ///
    /// Computed by the caller from the memories that went in, and read by the
    /// gate. Sensitivity is the maximum over inputs, never the average.
    pub max_sensitivity: Sensitivity,
    /// Which task this serves, for the audit log.
    pub task: TaskKind,
    /// Sampling temperature.
    pub temperature: f32,
    /// Cap on generated tokens.
    pub max_tokens: u32,
}

/// One message in a request.
///
/// Corpus text is always [`Role::CorpusData`], never [`Role::User`]. The
/// separation is the point: it means "ignore previous instructions" arriving
/// from an ingested nostr note lands in a channel the prompt builder frames as
/// data (SPEC §11.3).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Message {
    /// Who is speaking.
    pub role: Role,
    /// What they said.
    pub content: String,
}

/// Which channel a message occupies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Role {
    /// The real user, talking to their ghost.
    User,
    /// A previous model turn.
    Assistant,
    /// Corpus content: delimited, typed, and never an instruction.
    CorpusData,
}

/// What a request is for.
///
/// Recorded in the egress log so a user auditing what left their device sees
/// *why*, not just how many bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum TaskKind {
    /// Memoria cluster extraction.
    Extraction,
    /// Persona distillation.
    Distillation,
    /// Quest generation.
    QuestGeneration,
    /// The user talking to their ghost.
    Conversation,
    /// Embedding. Always local (SPEC Q13).
    Embedding,
}

/// What a model returned.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Completion {
    /// The generated text.
    pub text: String,
    /// Which model produced it.
    pub model: String,
    /// Prompt tokens consumed.
    pub prompt_tokens: u32,
    /// Tokens generated.
    pub completion_tokens: u32,
    /// Why generation stopped.
    pub finish_reason: FinishReason,
}

/// Why generation stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum FinishReason {
    /// The model finished.
    Stop,
    /// The token cap was hit. Structured output must treat this as a failure —
    /// truncated JSON that happens to parse is worse than no output.
    Length,
    /// The provider's content filter intervened.
    ContentFilter,
}
