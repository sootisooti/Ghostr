//! Test doubles for the traits that would otherwise need I/O.

use async_trait::async_trait;
use ghostr_core::time::Timestamp;
use ghostr_llm::egress::{EgressEntry, EgressLog, EgressSummary};
use ghostr_llm::model::{Completion, CompletionRequest, LanguageModel, ModelDescriptor};
use ghostr_llm::schema::Schema;

/// A model that returns canned responses in order.
///
/// Makes the pipeline testable without inference, and makes the *interesting*
/// cases reachable: a model that returns invalid JSON, a truncated response, a
/// schema violation. Those paths are hard to trigger against a real model and
/// are exactly where the extraction path's defences live.
#[derive(Debug, Default)]
pub struct ScriptedModel {
    responses: std::sync::Mutex<Vec<ScriptedResponse>>,
    calls: std::sync::Mutex<Vec<CompletionRequest>>,
}

/// One scripted response.
#[derive(Debug, Clone, PartialEq)]
pub enum ScriptedResponse {
    /// Return this text.
    Text(String),
    /// Return output that will fail schema validation.
    SchemaViolation,
    /// Return output truncated at the token limit.
    Truncated(String),
    /// Fail as if the transport died.
    TransportFailure(String),
}

impl ScriptedModel {
    /// A model that returns these responses in order.
    #[must_use]
    pub fn new(responses: Vec<ScriptedResponse>) -> Self {
        todo!("store the responses and an empty call log")
    }

    /// Every request the model received.
    ///
    /// The assertion surface for the property that matters most: that corpus
    /// text arrived as [`Role::CorpusData`](ghostr_llm::model::Role::CorpusData)
    /// and never in the system prompt (SPEC §11.3).
    ///
    /// # Panics
    ///
    /// Panics if the internal lock is poisoned.
    #[must_use]
    pub fn calls(&self) -> Vec<CompletionRequest> {
        todo!("clone the recorded calls")
    }

    /// Whether any recorded call put corpus text in the instruction channel.
    ///
    /// A test asserting this returns `false` is the regression guard for the
    /// injection boundary.
    #[must_use]
    pub fn any_corpus_in_system_prompt(&self) -> bool {
        todo!("scan recorded calls for corpus text inside the system field")
    }
}

#[async_trait]
impl LanguageModel for ScriptedModel {
    fn descriptor(&self) -> ModelDescriptor {
        todo!("return a Local, Baseline descriptor")
    }

    async fn complete(&self, request: CompletionRequest) -> ghostr_llm::Result<Completion> {
        todo!("record the call and pop the next scripted response")
    }

    async fn complete_with_schema(
        &self,
        request: CompletionRequest,
        schema: &Schema,
    ) -> ghostr_llm::Result<String> {
        todo!("record the call and pop the next scripted response")
    }
}

/// An egress log that keeps everything in memory.
///
/// Lets a test assert the whole record: that a deny was logged as well as an
/// allow, and that the entry was written before any transmission.
#[derive(Debug, Default)]
pub struct RecordingEgressLog {
    entries: std::sync::Mutex<Vec<EgressEntry>>,
}

impl RecordingEgressLog {
    /// Everything recorded so far.
    ///
    /// # Panics
    ///
    /// Panics if the internal lock is poisoned.
    #[must_use]
    pub fn entries(&self) -> Vec<EgressEntry> {
        todo!("clone the recorded entries")
    }
}

#[async_trait]
impl EgressLog for RecordingEgressLog {
    async fn record(&self, entry: EgressEntry) -> ghostr_llm::Result<()> {
        todo!("append the entry")
    }

    async fn since(&self, from: Timestamp) -> ghostr_llm::Result<Vec<EgressEntry>> {
        todo!("filter the recorded entries")
    }

    async fn summary(&self, from: Timestamp, to: Timestamp) -> ghostr_llm::Result<EgressSummary> {
        todo!("total the recorded entries in the window")
    }
}
