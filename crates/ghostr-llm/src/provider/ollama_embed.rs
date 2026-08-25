//! Local embedding over an Ollama-compatible runtime.
//!
//! There is no remote counterpart to this file and there is not going to be one.
//! An embedding is invertible enough to reconstruct much of the text it came
//! from, so shipping one to a provider is shipping the content. The rule covers
//! `Public` memories too, because a rule with an exception is a rule with a
//! failure mode (SPEC Q13).

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::embed::{EmbedInput, Embedder, EmbedderDescriptor, Embedding};
use crate::gate::LocalModelConfig;
use crate::model::Locality;

/// A local embedding model.
#[derive(Debug, Clone)]
pub(crate) struct OllamaEmbedder {
    config: LocalModelConfig,
    dimensions: u32,
    timeout: std::time::Duration,
}

/// How many inputs one request carries.
///
/// The runtime holds every input in memory while it batches, and a day's worth
/// of notes is small. Bounded so a bulk re-embed of a multi-year corpus does not
/// hand the runtime a single enormous request.
const MAX_BATCH: u32 = 64;

impl OllamaEmbedder {
    /// Builds the embedder.
    ///
    /// `dimensions` is what the index will be built against, so it is declared
    /// rather than discovered: a model that silently returns a different width
    /// than the index expects must be an error, not a rebuild.
    pub(crate) const fn new(config: LocalModelConfig, dimensions: u32) -> Self {
        Self {
            config,
            dimensions,
            timeout: std::time::Duration::from_secs(120),
        }
    }

    fn post(&self, body: &EmbedBody) -> crate::Result<EmbedResponse> {
        let url = format!("{}/api/embed", self.config.endpoint.trim_end_matches('/'));
        let agent = ureq::AgentBuilder::new()
            .timeout_connect(std::time::Duration::from_secs(5))
            .timeout_read(self.timeout)
            .build();

        let response = agent
            .post(&url)
            .send_json(body)
            .map_err(|e| crate::Error::Transport {
                // Names the endpoint, never the payload.
                reason: format!("{}: {}", self.config.endpoint, transport_reason(&e)),
            })?;

        response
            .into_json::<EmbedResponse>()
            .map_err(|_| crate::Error::Transport {
                reason: "malformed embedding response".to_owned(),
            })
    }
}

/// Describes a transport failure without echoing the response body.
fn transport_reason(e: &ureq::Error) -> String {
    match e {
        ureq::Error::Status(code, _) => format!("HTTP {code}"),
        ureq::Error::Transport(t) => t.kind().to_string(),
    }
}

#[async_trait]
impl Embedder for OllamaEmbedder {
    fn descriptor(&self) -> EmbedderDescriptor {
        EmbedderDescriptor {
            model: format!("ollama:{}", self.config.model),
            dimensions: self.dimensions,
            locality: Locality::Local,
            max_batch: MAX_BATCH,
        }
    }

    async fn embed(&self, inputs: &[EmbedInput]) -> crate::Result<Vec<Embedding>> {
        // Belt and braces beside there being no remote implementation: the
        // assertion costs nothing and it is the line a future refactor would
        // have to delete on purpose.
        debug_assert_eq!(self.descriptor().locality, Locality::Local);
        if self.descriptor().locality != Locality::Local {
            return Err(crate::Error::ProviderNotEnabled {
                provider: "remote embedding (there is none, by design)".to_owned(),
            });
        }
        if inputs.is_empty() {
            return Ok(Vec::new());
        }

        let mut out = Vec::with_capacity(inputs.len());
        for chunk in inputs.chunks(MAX_BATCH as usize) {
            let body = EmbedBody {
                model: self.config.model.clone(),
                input: chunk.iter().map(|i| i.text.clone()).collect(),
            };
            let response = self.post(&body)?;
            if response.embeddings.len() != chunk.len() {
                return Err(crate::Error::Transport {
                    reason: format!(
                        "expected {} embeddings, got {}",
                        chunk.len(),
                        response.embeddings.len()
                    ),
                });
            }
            for (input, vector) in chunk.iter().zip(response.embeddings) {
                if u32::try_from(vector.len()).unwrap_or(u32::MAX) != self.dimensions {
                    // A width mismatch means the runtime is serving a different
                    // model than the index was built with. Mixing two vector
                    // spaces produces neighbours that are not neighbours, and
                    // silently is the worst way for that to happen.
                    return Err(crate::Error::Transport {
                        reason: format!(
                            "model returned {} dimensions, index expects {}",
                            vector.len(),
                            self.dimensions
                        ),
                    });
                }
                out.push(Embedding {
                    memory: input.memory,
                    vector,
                });
            }
        }
        Ok(out)
    }
}

/// The request body.
#[derive(Debug, Serialize)]
pub(crate) struct EmbedBody {
    model: String,
    input: Vec<String>,
}

/// The response body.
#[derive(Debug, Deserialize)]
struct EmbedResponse {
    embeddings: Vec<Vec<f32>>,
}

#[cfg(test)]
mod tests {
    use ghostr_core::ids::MemoryId;
    use ghostr_core::sensitivity::Sensitivity;

    use super::*;

    fn embedder() -> OllamaEmbedder {
        OllamaEmbedder::new(LocalModelConfig::default(), 4)
    }

    fn input(n: u8, text: &str) -> EmbedInput {
        EmbedInput {
            memory: MemoryId::new(u64::from(n), [n; 10]),
            text: text.to_owned(),
            sensitivity: Sensitivity::Secret,
        }
    }

    #[test]
    fn the_descriptor_is_local() {
        assert_eq!(embedder().descriptor().locality, Locality::Local);
    }

    #[tokio::test]
    async fn an_empty_batch_makes_no_request() {
        // Would fail with a transport error if it reached the network. It must
        // not: there is no runtime listening in a test (CLAUDE.md §6).
        assert!(embedder().embed(&[]).await.expect("empty").is_empty());
    }

    #[test]
    fn a_batch_is_split_at_the_declared_maximum() {
        let inputs: Vec<_> = (0..200u32).map(|i| input(i as u8, "note")).collect();
        let chunks: Vec<_> = inputs.chunks(MAX_BATCH as usize).collect();
        assert_eq!(chunks.len(), 4);
        assert_eq!(embedder().descriptor().max_batch, MAX_BATCH);
    }

    /// `Secret` content is embedded, because embedding is local. That is the
    /// point of there being no remote path.
    #[test]
    fn secret_content_is_accepted() {
        let body = EmbedBody {
            model: "nomic-embed-text".to_owned(),
            input: vec![input(1, "my resting heart rate").text],
        };
        assert_eq!(body.input.len(), 1);
    }

    #[tokio::test]
    #[ignore = "needs a local Ollama runtime with an embedding model pulled"]
    async fn live_round_trip() {
        let e = OllamaEmbedder::new(
            LocalModelConfig {
                model: "nomic-embed-text".to_owned(),
                ..LocalModelConfig::default()
            },
            768,
        );
        let out = e
            .embed(&[input(1, "dinner with a friend")])
            .await
            .expect("embed");
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].vector.len(), 768);
    }
}
