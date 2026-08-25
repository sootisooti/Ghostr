//! An OpenAI-compatible remote provider.
//!
//! Exists so the [`LanguageModel`] trait is proven against two shapes rather
//! than one, and so the gate has something real to gate (ROADMAP M1).
//!
//! # This type is unreachable from outside the crate
//!
//! It is `pub(crate)`, and the only public constructor that produces one is
//! [`gate::remote`](crate::gate::remote), which requires a policy, a log, and a
//! redactor and returns a [`GatedModel`](crate::gate::GatedModel). There is no
//! path by which a caller obtains this unwrapped (ARCHITECTURE §4.2).
//!
//! The `remote` feature is off by default, so a stock build does not contain
//! this file's code at all.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::gate::RemoteModelConfig;
use crate::model::{
    CapabilityTier, Completion, CompletionRequest, FinishReason, LanguageModel, Locality,
    ModelDescriptor, Role,
};
use crate::schema::Schema;

/// A remote chat-completions model.
#[derive(Clone)]
pub(crate) struct RemoteModel {
    config: RemoteModelConfig,
    endpoint: String,
    api_key: String,
}

impl core::fmt::Debug for RemoteModel {
    /// Prints the provider and model, never the credential (SPEC I8).
    ///
    /// A derived `Debug` here printed the API key, which a test caught. Any
    /// struct holding a secret needs this written by hand — the derive is the
    /// bug, and it is silent until something formats the value into a log or a
    /// panic message.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RemoteModel")
            .field("provider", &self.config.provider)
            .field("model", &self.config.model)
            .field("endpoint", &self.endpoint)
            .field("api_key", &"<redacted>")
            .finish()
    }
}

impl RemoteModel {
    /// Builds a provider, reading its credential from the environment.
    ///
    /// The key is read here rather than carried in [`RemoteModelConfig`], so it
    /// never sits in a `Debug`-printable struct that could reach a log or a
    /// crash report. `Debug` for this type omits it too.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ProviderNotEnabled`](crate::Error::ProviderNotEnabled)
    /// if no credential is configured — refusing rather than sending an
    /// unauthenticated request that would fail confusingly at the provider.
    pub(crate) fn new(config: RemoteModelConfig) -> crate::Result<Self> {
        let upper = config.provider.to_uppercase();
        Self::with_credential(
            config,
            std::env::var(format!("GHOSTR_{upper}_API_KEY")).ok(),
            std::env::var(format!("GHOSTR_{upper}_ENDPOINT")).ok(),
        )
    }

    /// Builds a provider from explicit parts.
    ///
    /// Reading the environment is confined to [`RemoteModel::new`] so that this
    /// — the part with the actual logic — is a pure function and its tests do
    /// not depend on ambient process state (CLAUDE.md §6: determinism is
    /// mandatory).
    ///
    /// # Errors
    ///
    /// Returns [`Error::ProviderNotEnabled`](crate::Error::ProviderNotEnabled)
    /// if no credential is supplied.
    pub(crate) fn with_credential(
        config: RemoteModelConfig,
        api_key: Option<String>,
        endpoint: Option<String>,
    ) -> crate::Result<Self> {
        let api_key = api_key.filter(|k| !k.trim().is_empty()).ok_or_else(|| {
            crate::Error::ProviderNotEnabled {
                provider: config.provider.clone(),
            }
        })?;
        Ok(Self {
            config,
            endpoint: endpoint.unwrap_or_else(|| "https://api.openai.com/v1".to_owned()),
            api_key,
        })
    }

    /// Builds the request body. Pure, so it is testable without a network.
    pub(crate) fn build_body(
        &self,
        request: &CompletionRequest,
        schema: Option<&Schema>,
    ) -> ChatBody {
        ChatBody {
            model: self.config.model.clone(),
            messages: std::iter::once(ChatMessage {
                role: "system".to_owned(),
                content: request.system.clone(),
            })
            .chain(request.messages.iter().map(|m| {
                ChatMessage {
                    role: match m.role {
                        Role::Assistant => "assistant",
                        // Corpus data is a user turn, never a system one (SPEC §11.3).
                        _ => "user",
                    }
                    .to_owned(),
                    content: m.content.clone(),
                }
            }))
            .collect(),
            temperature: request.temperature,
            max_tokens: request.max_tokens,
            response_format: schema.map(|s| ResponseFormat {
                kind: "json_schema".to_owned(),
                json_schema: JsonSchema {
                    name: s.name.to_owned(),
                    schema: s.json.clone(),
                    strict: true,
                },
            }),
        }
    }
}

#[async_trait]
impl LanguageModel for RemoteModel {
    fn descriptor(&self) -> ModelDescriptor {
        ModelDescriptor {
            id: format!("{}:{}", self.config.provider, self.config.model),
            // The field the gate reads. Being wrong here would route Secret
            // content at a provider, so it is a constant, not a computation.
            locality: Locality::Remote,
            context_tokens: 128_000,
            tier: CapabilityTier::Strong,
            native_schema: true,
        }
    }

    async fn complete(&self, request: CompletionRequest) -> crate::Result<Completion> {
        let body = self.build_body(&request, None);
        let response = self.post(&body)?;
        Ok(response.into_completion(&self.config.model))
    }

    async fn complete_with_schema(
        &self,
        request: CompletionRequest,
        schema: &Schema,
    ) -> crate::Result<String> {
        let body = self.build_body(&request, Some(schema));
        let response = self.post(&body)?;
        let choice = response
            .choices
            .into_iter()
            .next()
            .ok_or(crate::Error::SchemaViolation)?;
        if choice.finish_reason.as_deref() == Some("length") {
            return Err(crate::Error::SchemaViolation);
        }
        Ok(choice.message.content)
    }
}

impl RemoteModel {
    fn post(&self, body: &ChatBody) -> crate::Result<ChatResponse> {
        let url = format!("{}/chat/completions", self.endpoint.trim_end_matches('/'));
        let agent = ureq::AgentBuilder::new()
            .timeout_connect(std::time::Duration::from_secs(10))
            .timeout_read(std::time::Duration::from_secs(120))
            .build();

        agent
            .post(&url)
            .set("Authorization", &format!("Bearer {}", self.api_key))
            .send_json(body)
            .map_err(|e| match e {
                ureq::Error::Status(code, _) => crate::Error::ProviderRefused {
                    // The status only. A provider error body can echo the prompt
                    // back, which would put corpus content into our logs.
                    status: format!("HTTP {code}"),
                },
                ureq::Error::Transport(t) => crate::Error::Transport {
                    reason: t.kind().to_string(),
                },
            })?
            .into_json::<ChatResponse>()
            .map_err(|_| crate::Error::Transport {
                reason: "malformed response body".to_owned(),
            })
    }
}

/// A chat-completions request body.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub(crate) struct ChatBody {
    pub(crate) model: String,
    pub(crate) messages: Vec<ChatMessage>,
    pub(crate) temperature: f32,
    pub(crate) max_tokens: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) response_format: Option<ResponseFormat>,
}

/// One message.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct ChatMessage {
    pub(crate) role: String,
    pub(crate) content: String,
}

/// Structured-output request.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub(crate) struct ResponseFormat {
    #[serde(rename = "type")]
    pub(crate) kind: String,
    pub(crate) json_schema: JsonSchema,
}

/// The schema envelope.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub(crate) struct JsonSchema {
    pub(crate) name: String,
    pub(crate) schema: serde_json::Value,
    pub(crate) strict: bool,
}

/// A chat-completions response.
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct ChatResponse {
    pub(crate) choices: Vec<Choice>,
    #[serde(default)]
    pub(crate) usage: Usage,
}

/// One choice.
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct Choice {
    pub(crate) message: ChatMessage,
    #[serde(default)]
    pub(crate) finish_reason: Option<String>,
}

/// Token accounting.
#[derive(Debug, Clone, Copy, Default, Deserialize)]
pub(crate) struct Usage {
    #[serde(default)]
    pub(crate) prompt_tokens: u32,
    #[serde(default)]
    pub(crate) completion_tokens: u32,
}

impl ChatResponse {
    fn into_completion(self, model: &str) -> Completion {
        let finish = self
            .choices
            .first()
            .and_then(|c| c.finish_reason.clone())
            .unwrap_or_default();
        Completion {
            text: self
                .choices
                .into_iter()
                .next()
                .map(|c| c.message.content)
                .unwrap_or_default(),
            model: model.to_owned(),
            prompt_tokens: self.usage.prompt_tokens,
            completion_tokens: self.usage.completion_tokens,
            finish_reason: match finish.as_str() {
                "length" => FinishReason::Length,
                "content_filter" => FinishReason::ContentFilter,
                _ => FinishReason::Stop,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Message, TaskKind};

    fn config() -> RemoteModelConfig {
        RemoteModelConfig {
            provider: "acme".to_owned(),
            model: "gpt-test".to_owned(),
            enabled_tasks: vec![TaskKind::Conversation],
        }
    }

    fn model() -> RemoteModel {
        RemoteModel {
            config: config(),
            endpoint: "https://example.invalid/v1".to_owned(),
            api_key: "sk-test-key-never-real".to_owned(),
        }
    }

    fn request() -> CompletionRequest {
        CompletionRequest {
            system: "instructions".to_owned(),
            messages: vec![Message {
                role: Role::CorpusData,
                content: "saw @nan today".to_owned(),
            }],
            max_sensitivity: ghostr_core::sensitivity::Sensitivity::Private,
            task: TaskKind::Conversation,
            temperature: 0.0,
            max_tokens: 256,
        }
    }

    /// The field the gate reads to decide whether Secret may pass. Being wrong
    /// here would route Secret content at a provider.
    #[test]
    fn the_descriptor_is_remote_and_refuses_secret() {
        let d = model().descriptor();
        assert_eq!(d.locality, Locality::Remote);
        assert!(!d.accepts(ghostr_core::sensitivity::Sensitivity::Secret));
        assert!(d.accepts(ghostr_core::sensitivity::Sensitivity::Private));
    }

    #[test]
    fn corpus_content_never_becomes_a_system_message() {
        let body = model().build_body(&request(), None);
        let system: Vec<_> = body
            .messages
            .iter()
            .filter(|m| m.role == "system")
            .collect();
        assert_eq!(system.len(), 1);
        assert!(!system[0].content.contains("saw @nan"));
    }

    /// The credential must not be reachable through Debug.
    ///
    /// Regression: `#[derive(Debug)]` printed the key. It is silent until
    /// something formats the value into a log line or a panic message, which is
    /// exactly when it matters (SPEC I8).
    #[test]
    fn debug_does_not_expose_the_api_key() {
        let rendered = format!("{:?}", model());
        assert!(
            !rendered.contains("sk-test-key-never-real"),
            "key leaked: {rendered}"
        );
        assert!(rendered.contains("<redacted>"));
        // The non-secret fields stay useful for debugging.
        assert!(rendered.contains("acme"));
    }

    /// The body is what would be transmitted; it must carry no credential.
    #[test]
    fn the_request_body_carries_no_credential() {
        let rendered =
            serde_json::to_string(&model().build_body(&request(), None)).expect("serialise");
        assert!(!rendered.contains("sk-test-key-never-real"));
        assert!(!rendered.contains("Bearer"));
    }

    /// Refusing beats sending an unauthenticated request that fails confusingly
    /// at the provider. Tested through the pure constructor, so the result does
    /// not depend on the ambient environment.
    #[test]
    fn a_missing_or_blank_credential_refuses_construction() {
        for credential in [None, Some(String::new()), Some("   ".to_owned())] {
            assert!(
                matches!(
                    RemoteModel::with_credential(config(), credential.clone(), None),
                    Err(crate::Error::ProviderNotEnabled { .. })
                ),
                "credential {credential:?} should have been refused"
            );
        }
        assert!(RemoteModel::with_credential(config(), Some("sk-real".to_owned()), None).is_ok());
    }

    #[test]
    fn the_default_endpoint_is_used_when_none_is_given() {
        let m = RemoteModel::with_credential(config(), Some("sk-x".to_owned()), None)
            .expect("construct");
        assert!(m.endpoint.starts_with("https://"));
    }

    #[test]
    fn a_schema_becomes_a_strict_response_format() {
        let schema = Schema {
            name: "extraction",
            json: serde_json::json!({"type": "object"}),
        };
        let body = model().build_body(&request(), Some(&schema));
        let rf = body.response_format.expect("present");
        assert_eq!(rf.kind, "json_schema");
        assert!(
            rf.json_schema.strict,
            "strict mode or the schema is only a suggestion"
        );
    }

    #[test]
    fn a_truncated_choice_maps_to_length() {
        let response = ChatResponse {
            choices: vec![Choice {
                message: ChatMessage {
                    role: "assistant".to_owned(),
                    content: "x".to_owned(),
                },
                finish_reason: Some("length".to_owned()),
            }],
            usage: Usage::default(),
        };
        assert_eq!(
            response.into_completion("m").finish_reason,
            FinishReason::Length
        );
    }
}
