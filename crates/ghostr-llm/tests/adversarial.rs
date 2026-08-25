//! The hostile suite. Permanent, not a one-off check.
//!
//! CLAUDE.md §6 requires this to live in CI for the same reason a crypto test
//! vector does: the defence is only real while something keeps checking it. Each
//! test below is a table over every [`InjectionKind`], so a defence is never
//! proven against one attack and assumed for the rest.
//!
//! What is being asserted throughout is **structural**, not behavioural. None of
//! these tests claims a model will resist an injection — that is not a property
//! anyone can guarantee. They claim the injected text never reaches the channel
//! where resisting it would be necessary (THREAT_MODEL §T7).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use ghostr_core::sensitivity::{Sensitivity, TrustLevel};
use ghostr_llm::detect::PatternDetector;
use ghostr_llm::egress::{DenyReason, EgressDecision, EgressPolicy, EgressRequest};
use ghostr_llm::model::{Locality, Role, TaskKind};
use ghostr_llm::prompt::{PromptBuilder, TokenBudget};
use ghostr_llm::redact::SecretDetector as _;
use ghostr_llm::{StandardPolicy, schema::StructuredOutput};
use ghostr_testkit::adversarial::{InjectionKind, injected_memory, secret_samples};
use ghostr_testkit::{ScriptedModel, secret_bearing_text};

/// The property the whole prompt design rests on, across every attack.
#[test]
fn no_injection_reaches_the_instruction_channel() {
    for kind in InjectionKind::all() {
        let request = PromptBuilder::new(TaskKind::Extraction, TokenBudget(4096))
            .corpus(&[injected_memory(*kind)], TrustLevel::ThirdParty)
            .build()
            .expect("build");

        // The system prompt is Ghostr's, whole and unmodified.
        assert_eq!(
            request.system,
            ghostr_llm::prompt::system_prompt(TaskKind::Extraction).text,
            "{} altered the system prompt",
            kind.label()
        );

        // And the attack text is present exactly once, in the data channel.
        let corpus: Vec<_> = request
            .messages
            .iter()
            .filter(|m| m.role == Role::CorpusData)
            .collect();
        assert_eq!(corpus.len(), 1, "{}", kind.label());
        assert!(
            !request
                .system
                .contains(kind.text().lines().next().unwrap_or("")),
            "{} leaked into the system prompt",
            kind.label()
        );
    }
}

/// A note cannot close its own block. One opening delimiter, one closing one,
/// whatever the note contains.
#[test]
fn no_injection_escapes_its_delimiters() {
    for kind in InjectionKind::all() {
        let request = PromptBuilder::new(TaskKind::Extraction, TokenBudget(4096))
            .corpus(&[injected_memory(*kind)], TrustLevel::ThirdParty)
            .build()
            .expect("build");
        let content = &request.messages[0].content;

        assert_eq!(
            content.matches("<corpus trust=").count(),
            1,
            "{} opened a second block",
            kind.label()
        );
        assert_eq!(
            content.matches("</corpus>").count(),
            1,
            "{} closed the block early",
            kind.label()
        );
    }
}

/// Third-party content is labelled as such in the markup, so the model is told
/// in the same breath that somebody else's text is present.
#[test]
fn every_injection_is_labelled_untrusted() {
    for kind in InjectionKind::all() {
        let request = PromptBuilder::new(TaskKind::Extraction, TokenBudget(4096))
            .corpus(&[injected_memory(*kind)], TrustLevel::ThirdParty)
            .build()
            .expect("build");
        assert!(
            request.messages[0]
                .content
                .contains("third-party-untrusted"),
            "{} was not labelled",
            kind.label()
        );
    }
}

/// The regression guard, run against the real builder rather than a mock.
#[tokio::test]
async fn the_recorded_calls_show_no_corpus_in_any_system_prompt() {
    use ghostr_llm::model::LanguageModel as _;

    let model = ScriptedModel::always("ok");
    for kind in InjectionKind::all() {
        let request = PromptBuilder::new(TaskKind::Extraction, TokenBudget(4096))
            .corpus(&[injected_memory(*kind)], TrustLevel::ThirdParty)
            .build()
            .expect("build");
        model.complete(request).await.expect("ok");
    }
    assert_eq!(model.call_count(), InjectionKind::all().len());
    assert!(!model.any_corpus_in_system_prompt());
}

/// Schema mimicry is the attack the validator exists for: text shaped like the
/// extraction output, hoping to be read as it. It must not validate.
#[test]
fn text_shaped_like_the_schema_does_not_validate_as_it() {
    #[derive(serde::Deserialize)]
    struct Extraction {
        #[allow(dead_code)]
        people: Vec<String>,
    }
    impl StructuredOutput for Extraction {
        fn schema() -> ghostr_llm::Schema {
            ghostr_llm::Schema {
                name: "extraction",
                json: serde_json::json!({
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["people"],
                    "properties": {
                        "people": {
                            "type": "array",
                            "items": { "type": "string", "maxLength": 64 }
                        }
                    }
                }),
            }
        }
    }

    let mimic: serde_json::Value =
        serde_json::from_str(InjectionKind::SchemaMimicry.text()).expect("it is valid JSON");
    // Valid JSON, and still refused: it carries fields nobody asked for.
    assert!(Extraction::schema().validate(&mimic).is_err());
}

/// SPEC §11.2, rule 1. Every injection, marked `Secret`, denied at every
/// policy configuration — including a policy that enables everything.
#[test]
fn secret_injections_are_denied_under_every_policy() {
    let policies = [
        StandardPolicy::deny_all(),
        StandardPolicy::enabling(vec![
            ("acme".to_owned(), TaskKind::Extraction),
            ("acme".to_owned(), TaskKind::Summarization),
            ("acme".to_owned(), TaskKind::Conversation),
        ]),
    ];

    for policy in &policies {
        for kind in InjectionKind::all() {
            let decision = policy.evaluate(&EgressRequest {
                provider: "acme".to_owned(),
                locality: Locality::Remote,
                max_sensitivity: Sensitivity::Secret,
                task: TaskKind::Extraction,
                payload_bytes: kind.text().len() as u32,
                detected_secrets: Vec::new(),
                entities: Vec::new(),
            });
            assert_eq!(
                decision,
                EgressDecision::Deny {
                    reason: DenyReason::SecretContent
                },
                "{} escaped under {}",
                kind.label(),
                policy.policy_id()
            );
        }
    }
}

/// Every secret kind is found. A table so a failure names *which* one went
/// undetected, rather than only that the count was wrong.
#[test]
fn every_planted_secret_is_detected() {
    for (label, sample) in secret_samples() {
        let findings = PatternDetector.scan(sample);
        assert!(!findings.is_empty(), "{label} went undetected");
    }
}

/// A payload carrying several secrets at once finds all of them, not the first.
#[test]
fn a_payload_with_many_secrets_finds_more_than_one() {
    let findings = PatternDetector.scan(secret_bearing_text());
    let mut kinds: Vec<_> = findings.iter().map(|f| f.kind).collect();
    kinds.dedup();
    let distinct = kinds.iter().collect::<std::collections::HashSet<_>>().len();
    assert!(
        distinct >= 4,
        "only found {distinct} distinct kinds: {kinds:?}"
    );
}

/// I8. A finding names a kind and a span, never the value — otherwise
/// detecting a secret would be a way of logging it.
#[test]
fn findings_never_carry_the_secret_they_found() {
    let findings = PatternDetector.scan(secret_bearing_text());
    let rendered = format!("{findings:?}");
    for fragment in ["4242", "hunter2", "sk-test", "qqqq", "MIIEvQ"] {
        assert!(
            !rendered.contains(fragment),
            "a finding leaked {fragment}: {rendered}"
        );
    }
}

/// Detected secrets deny at the gate, under a policy that would otherwise
/// allow the request.
#[test]
fn a_detected_secret_denies_an_otherwise_permitted_request() {
    let policy = StandardPolicy::enabling(vec![("acme".to_owned(), TaskKind::Summarization)]);
    let findings = PatternDetector.scan(secret_bearing_text());
    assert!(!findings.is_empty(), "the fixture must carry secrets");

    let decision = policy.evaluate(&EgressRequest {
        provider: "acme".to_owned(),
        locality: Locality::Remote,
        // Private, not Secret: the deny must come from detection, not from
        // sensitivity, or this test proves nothing about the detector.
        max_sensitivity: Sensitivity::Private,
        task: TaskKind::Summarization,
        payload_bytes: 512,
        detected_secrets: findings.iter().map(|f| f.kind).collect(),
        entities: Vec::new(),
    });
    assert!(matches!(decision, EgressDecision::Deny { .. }));
}
