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
    default: std::sync::Mutex<Option<ScriptedResponse>>,
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
        Self {
            // Reversed so `pop` takes them in the order they were written. A
            // script that ran backwards would be a maddening test failure.
            responses: std::sync::Mutex::new(responses.into_iter().rev().collect()),
            calls: std::sync::Mutex::new(Vec::new()),
            default: std::sync::Mutex::new(None),
        }
    }

    /// A model that always returns the same text.
    ///
    /// For tests where the model's answer is not what is under test.
    #[must_use]
    pub fn always(text: &str) -> Self {
        Self::new(Vec::new()).with_default(text)
    }

    /// Sets the response used once the script runs out.
    #[must_use]
    pub fn with_default(self, text: &str) -> Self {
        *self
            .default
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) =
            Some(ScriptedResponse::Text(text.to_owned()));
        self
    }

    /// How many times the model was called.
    ///
    /// # Panics
    ///
    /// Panics if the internal lock is poisoned.
    #[must_use]
    pub fn call_count(&self) -> usize {
        self.calls
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len()
    }

    /// Takes the next scripted response, or the default.
    fn next(&self) -> ScriptedResponse {
        let popped = self
            .responses
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .pop();
        popped.unwrap_or_else(|| {
            self.default
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone()
                // Running past the end of a script with no default is a test
                // bug, and a transport failure is how it surfaces: loudly, on
                // the call that overran, rather than as a silent empty string.
                .unwrap_or_else(|| {
                    ScriptedResponse::TransportFailure("script exhausted".to_owned())
                })
        })
    }

    /// Records a call and converts the next scripted response into a result.
    fn answer(&self, request: CompletionRequest) -> ghostr_llm::Result<String> {
        self.calls
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(request);
        match self.next() {
            ScriptedResponse::Text(text) => Ok(text),
            // Not valid JSON, so it fails at the parse before validation even
            // runs — which is the path a real model takes when it rambles.
            ScriptedResponse::SchemaViolation => Ok("{\"unexpected\": true".to_owned()),
            ScriptedResponse::Truncated(text) => Ok(text),
            ScriptedResponse::TransportFailure(reason) => {
                Err(ghostr_llm::Error::Transport { reason })
            }
        }
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
        self.calls
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Whether any recorded call put corpus text in the instruction channel.
    ///
    /// A test asserting this returns `false` is the regression guard for the
    /// injection boundary.
    #[must_use]
    pub fn any_corpus_in_system_prompt(&self) -> bool {
        use ghostr_llm::model::Role;

        self.calls().iter().any(|call| {
            call.messages
                .iter()
                .filter(|m| m.role == Role::CorpusData)
                .any(|m| {
                    // Compare on the corpus block's *contents*, not the whole
                    // message: the delimiters are Ghostr's own text and would
                    // match nothing useful. Any non-trivial line of a note
                    // appearing in the system prompt is the failure.
                    m.content
                        .lines()
                        .filter(|line| {
                            !line.starts_with("<corpus") && !line.starts_with("</corpus")
                        })
                        .filter(|line| line.trim().len() > 8)
                        .any(|line| call.system.contains(line.trim()))
                })
        })
    }
}

#[async_trait]
impl LanguageModel for ScriptedModel {
    fn descriptor(&self) -> ModelDescriptor {
        use ghostr_llm::model::{CapabilityTier, Locality};

        ModelDescriptor {
            id: "testkit:scripted".to_owned(),
            // Local, so a test using this double never trips the egress gate by
            // accident and never has to configure a policy to run.
            locality: Locality::Local,
            context_tokens: 8_192,
            tier: CapabilityTier::Baseline,
            native_schema: true,
        }
    }

    async fn complete(&self, request: CompletionRequest) -> ghostr_llm::Result<Completion> {
        use ghostr_llm::model::FinishReason;

        let truncated = matches!(
            self.responses
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .last(),
            Some(ScriptedResponse::Truncated(_))
        );
        let text = self.answer(request)?;
        Ok(Completion {
            text,
            model: "testkit:scripted".to_owned(),
            prompt_tokens: 0,
            completion_tokens: 0,
            finish_reason: if truncated {
                FinishReason::Length
            } else {
                FinishReason::Stop
            },
        })
    }

    async fn complete_with_schema(
        &self,
        request: CompletionRequest,
        schema: &Schema,
    ) -> ghostr_llm::Result<String> {
        let _ = schema;
        self.answer(request)
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
        self.entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Whether anything was denied.
    ///
    /// # Panics
    ///
    /// Panics if the internal lock is poisoned.
    #[must_use]
    pub fn any_denied(&self) -> bool {
        use ghostr_llm::egress::EgressDecision;

        self.entries()
            .iter()
            .any(|e| matches!(e.decision, EgressDecision::Deny { .. }))
    }

    /// Total bytes recorded as transmitted.
    ///
    /// Zero on a vault that only ever denied, which is the assertion worth
    /// making: not "a deny was logged" but "nothing went".
    ///
    /// # Panics
    ///
    /// Panics if the internal lock is poisoned.
    #[must_use]
    pub fn bytes_sent(&self) -> u64 {
        self.entries().iter().map(|e| u64::from(e.bytes_sent)).sum()
    }
}

#[async_trait]
impl EgressLog for RecordingEgressLog {
    async fn record(&self, entry: EgressEntry) -> ghostr_llm::Result<()> {
        self.entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(entry);
        Ok(())
    }

    async fn since(&self, from: Timestamp) -> ghostr_llm::Result<Vec<EgressEntry>> {
        Ok(self
            .entries()
            .into_iter()
            .filter(|e| e.at.utc_millis() >= from.utc_millis())
            .collect())
    }

    async fn summary(&self, from: Timestamp, to: Timestamp) -> ghostr_llm::Result<EgressSummary> {
        use ghostr_llm::egress::EgressDecision;

        let mut summary = EgressSummary::default();
        for entry in self.entries() {
            let at = entry.at.utc_millis();
            if at < from.utc_millis() || at > to.utc_millis() {
                continue;
            }
            match entry.decision {
                EgressDecision::Allow | EgressDecision::AllowRedacted(_) => {
                    summary.allowed += 1;
                    summary.bytes_sent += u64::from(entry.bytes_sent);
                }
                EgressDecision::Deny { .. } => summary.denied += 1,
            }
        }
        Ok(summary)
    }
}

#[cfg(test)]
mod tests {
    use ghostr_core::sensitivity::Sensitivity;
    use ghostr_llm::egress::{DenyReason, EgressDecision};
    use ghostr_llm::model::{Message, Role, TaskKind};

    use super::*;

    fn request(system: &str, corpus: &str) -> CompletionRequest {
        CompletionRequest {
            system: system.to_owned(),
            messages: vec![Message {
                role: Role::CorpusData,
                content: format!("<corpus trust=\"first-party\">\n{corpus}\n</corpus>"),
            }],
            max_sensitivity: Sensitivity::Private,
            task: TaskKind::Extraction,
            temperature: 0.0,
            max_tokens: 1024,
        }
    }

    fn entry(decision: EgressDecision, at: i64, bytes: u32) -> EgressEntry {
        EgressEntry {
            at: Timestamp::new(at, 0),
            provider: "acme".to_owned(),
            task: TaskKind::Summarization,
            decision,
            policy_id: "standard-v1".to_owned(),
            bytes_sent: bytes,
            payload_digest: None,
            entities_pseudonymised: 0,
        }
    }

    #[tokio::test]
    async fn scripted_responses_arrive_in_the_order_they_were_written() {
        let model = ScriptedModel::new(vec![
            ScriptedResponse::Text("first".to_owned()),
            ScriptedResponse::Text("second".to_owned()),
        ]);
        let a = model.complete(request("sys", "note")).await.expect("a");
        let b = model.complete(request("sys", "note")).await.expect("b");
        assert_eq!(a.text, "first");
        assert_eq!(b.text, "second");
        assert_eq!(model.call_count(), 2);
    }

    /// Overrunning a script is a test bug, and it surfaces loudly on the call
    /// that overran rather than as a silent empty string.
    #[tokio::test]
    async fn running_past_the_end_of_a_script_fails_loudly() {
        let model = ScriptedModel::new(vec![ScriptedResponse::Text("only".to_owned())]);
        model.complete(request("sys", "note")).await.expect("first");
        let err = model
            .complete(request("sys", "note"))
            .await
            .expect_err("must fail");
        assert!(matches!(err, ghostr_llm::Error::Transport { .. }));
    }

    #[tokio::test]
    async fn a_default_covers_calls_past_the_script() {
        let model = ScriptedModel::always("always this");
        for _ in 0..3 {
            let out = model.complete(request("sys", "note")).await.expect("ok");
            assert_eq!(out.text, "always this");
        }
    }

    /// The paths that are hard to reach against a real model, and exactly where
    /// the extraction path's defences live.
    #[tokio::test]
    async fn the_interesting_failure_modes_are_reachable() {
        let model = ScriptedModel::new(vec![
            ScriptedResponse::SchemaViolation,
            ScriptedResponse::Truncated("half a sen".to_owned()),
            ScriptedResponse::TransportFailure("connection reset".to_owned()),
        ]);
        let schema = ghostr_llm::schema::Schema {
            name: "anything",
            json: serde_json::json!({"type": "object"}),
        };

        // A schema violation returns text that will not even parse as JSON.
        let raw = model
            .complete_with_schema(request("sys", "note"), &schema)
            .await
            .expect("returns text");
        assert!(serde_json::from_str::<serde_json::Value>(&raw).is_err());

        let truncated = model.complete(request("sys", "note")).await.expect("ok");
        assert_eq!(
            truncated.finish_reason,
            ghostr_llm::model::FinishReason::Length
        );

        assert!(model.complete(request("sys", "note")).await.is_err());
    }

    /// The regression guard for the injection boundary. A test asserting this
    /// is `false` is what keeps corpus text out of the instruction channel
    /// (SPEC §11.3).
    #[tokio::test]
    async fn corpus_text_in_the_system_prompt_is_detected() {
        let clean = ScriptedModel::always("ok");
        clean
            .complete(request("You extract structure.", "Dinner with a friend."))
            .await
            .expect("ok");
        assert!(!clean.any_corpus_in_system_prompt());

        // And the detector actually fires when the property is violated —
        // a guard that cannot fail is not a guard.
        let leaking = ScriptedModel::always("ok");
        leaking
            .complete(request(
                "You extract structure. Dinner with a friend.",
                "Dinner with a friend.",
            ))
            .await
            .expect("ok");
        assert!(leaking.any_corpus_in_system_prompt());
    }

    /// The delimiters are Ghostr's own text, so their presence in a system
    /// prompt is not a leak — the note's contents are.
    #[tokio::test]
    async fn the_delimiters_themselves_do_not_count_as_a_leak() {
        let model = ScriptedModel::always("ok");
        model
            .complete(request(
                "Notes appear between <corpus> delimiters.",
                "Dinner with a friend.",
            ))
            .await
            .expect("ok");
        assert!(!model.any_corpus_in_system_prompt());
    }

    #[tokio::test]
    async fn the_egress_log_records_denies_as_well_as_allows() {
        let log = RecordingEgressLog::default();
        log.record(entry(EgressDecision::Allow, 1_000, 128))
            .await
            .expect("allow");
        log.record(entry(
            EgressDecision::Deny {
                reason: DenyReason::SecretContent,
            },
            2_000,
            0,
        ))
        .await
        .expect("deny");

        assert_eq!(log.entries().len(), 2);
        assert!(log.any_denied());
    }

    /// Not "a deny was logged" but "nothing went" — the assertion that
    /// actually matters.
    #[tokio::test]
    async fn a_log_of_only_denies_reports_no_bytes_sent() {
        let log = RecordingEgressLog::default();
        for at in [1_000, 2_000, 3_000] {
            log.record(entry(
                EgressDecision::Deny {
                    reason: DenyReason::SecretContent,
                },
                at,
                0,
            ))
            .await
            .expect("deny");
        }
        assert_eq!(log.bytes_sent(), 0);
        let summary = log
            .summary(Timestamp::new(0, 0), Timestamp::new(10_000, 0))
            .await
            .expect("summary");
        assert_eq!(summary.denied, 3);
        assert_eq!(summary.allowed, 0);
        assert_eq!(summary.bytes_sent, 0);
    }

    #[tokio::test]
    async fn since_and_summary_respect_their_windows() {
        let log = RecordingEgressLog::default();
        log.record(entry(EgressDecision::Allow, 1_000, 10))
            .await
            .expect("a");
        log.record(entry(EgressDecision::Allow, 5_000, 20))
            .await
            .expect("b");

        assert_eq!(
            log.since(Timestamp::new(2_000, 0))
                .await
                .expect("since")
                .len(),
            1
        );
        let summary = log
            .summary(Timestamp::new(0, 0), Timestamp::new(2_000, 0))
            .await
            .expect("summary");
        assert_eq!(summary.allowed, 1);
        assert_eq!(summary.bytes_sent, 10);
    }
}
