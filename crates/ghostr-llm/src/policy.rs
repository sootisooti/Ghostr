//! The egress policy: the decision procedure for what may leave the device.
//!
//! Rules, evaluated in this order (SPEC §11.2):
//!
//! 1. [`Sensitivity::Secret`] → **Deny**, unconditionally, no override.
//! 2. Egress disabled by the user → **Deny**.
//! 3. Provider not enabled *for this task* → **Deny**.
//! 4. A detected secret in the payload → **Deny**, surfaced not silently stripped.
//! 5. A local destination → **Allow** unchanged.
//! 6. Otherwise → **AllowRedacted**, carrying the plan that will be applied.
//!
//! # Why order matters
//!
//! `Secret` is checked first so that no later rule can ever be reached with
//! `Secret` content in hand. A policy that checked provider configuration first
//! would have a shape where "the provider is enabled" and "the content is
//! Secret" could both be true and the outcome would depend on which branch ran —
//! which is exactly the sort of thing that becomes a bypass after three
//! refactors.
//!
//! # Why detected secrets deny rather than redact
//!
//! Silently stripping an API key would be more convenient and is the wrong
//! call: the user needs to know a credential was sitting in their corpus. A
//! redactor that quietly cleans up teaches them nothing and leaves the
//! credential in the store.

use ghostr_core::sensitivity::Sensitivity;

use crate::egress::{DenyReason, EgressDecision, EgressPolicy, EgressRequest};
use crate::model::{Locality, TaskKind};
use crate::redact::RedactionPlan;

/// The standard policy.
///
/// There is deliberately no constructor that relaxes rule 1. A `Secret`-allowing
/// policy is a thing that would eventually be constructed by accident.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StandardPolicy {
    /// Whether the user has enabled egress at all. `false` by default.
    egress_enabled: bool,
    /// Which provider is permitted for which tasks.
    ///
    /// Per task, not global: enabling a provider for conversation must not
    /// silently enable it for bulk extraction over the whole corpus.
    enabled: Vec<(String, TaskKind)>,
}

impl Default for StandardPolicy {
    /// Egress off, nothing enabled.
    fn default() -> Self {
        Self {
            egress_enabled: false,
            enabled: Vec::new(),
        }
    }
}

impl StandardPolicy {
    /// A policy with egress enabled for the listed `(provider, task)` pairs.
    #[must_use]
    pub fn enabling(pairs: Vec<(String, TaskKind)>) -> Self {
        Self {
            egress_enabled: true,
            enabled: pairs,
        }
    }

    /// A policy that denies everything remote.
    ///
    /// The default build's policy, and the one every test starts from.
    #[must_use]
    pub fn deny_all() -> Self {
        Self::default()
    }

    fn permits(&self, provider: &str, task: TaskKind) -> bool {
        self.enabled
            .iter()
            .any(|(p, t)| p == provider && *t == task)
    }
}

impl EgressPolicy for StandardPolicy {
    fn evaluate(&self, request: &EgressRequest) -> EgressDecision {
        // Rule 1, first and unconditionally. Nothing below can be reached with
        // Secret content in hand.
        if request.max_sensitivity == Sensitivity::Secret && request.locality == Locality::Remote {
            return EgressDecision::Deny {
                reason: DenyReason::SecretContent,
            };
        }

        // A local destination is not egress. Checked after rule 1 so that the
        // Secret branch is unmissable when reading the function.
        if request.locality == Locality::Local {
            return EgressDecision::Allow;
        }

        if !self.egress_enabled {
            return EgressDecision::Deny {
                reason: DenyReason::UserDisabled,
            };
        }
        if !self.permits(&request.provider, request.task) {
            return EgressDecision::Deny {
                reason: DenyReason::ProviderNotEnabledForTask,
            };
        }
        if !request.detected_secrets.is_empty() {
            return EgressDecision::Deny {
                reason: DenyReason::SecretDetected,
            };
        }

        EgressDecision::AllowRedacted(RedactionPlan {
            // The concrete substitutions are filled in by the redactor, which
            // has the entity table. The policy decides *whether*, not *what*.
            pseudonymise: Vec::new(),
            strip: Vec::new(),
            truncated: false,
        })
    }

    fn policy_id(&self) -> &str {
        if self.egress_enabled {
            "standard/v1"
        } else {
            "deny-all/v1"
        }
    }
}

#[cfg(test)]
mod tests {
    use ghostr_core::ids::EntityId;

    use super::*;
    use crate::egress::SecretKind;

    const ALL_SENSITIVITIES: [Sensitivity; 3] = [
        Sensitivity::Public,
        Sensitivity::Private,
        Sensitivity::Secret,
    ];

    const ALL_TASKS: [TaskKind; 6] = [
        TaskKind::Extraction,
        TaskKind::Summarization,
        TaskKind::Distillation,
        TaskKind::QuestGeneration,
        TaskKind::Conversation,
        TaskKind::Embedding,
    ];

    fn request(
        locality: Locality,
        sensitivity: Sensitivity,
        task: TaskKind,
        secrets: Vec<SecretKind>,
    ) -> EgressRequest {
        EgressRequest {
            provider: "acme".to_owned(),
            locality,
            task,
            max_sensitivity: sensitivity,
            entities: vec![EntityId::new(1, [1u8; 10])],
            payload_bytes: 128,
            detected_secrets: secrets,
        }
    }

    /// SPEC I5 / §11.2 rule 1, exhaustively.
    ///
    /// Every policy configuration × every task × every provider-enabled state
    /// must deny `Secret` to a remote destination. This is the table test the
    /// ROADMAP names as an M1 exit criterion, and it is written to fail loudly
    /// if anyone ever adds an override.
    #[test]
    fn secret_is_denied_to_remote_under_every_policy_configuration() {
        let policies = [
            StandardPolicy::deny_all(),
            StandardPolicy::enabling(Vec::new()),
            StandardPolicy::enabling(ALL_TASKS.iter().map(|t| ("acme".to_owned(), *t)).collect()),
            // Even a policy that enables everything for every provider.
            StandardPolicy::enabling(
                ALL_TASKS
                    .iter()
                    .flat_map(|t| {
                        ["acme", "other", ""]
                            .iter()
                            .map(move |p| ((*p).to_owned(), *t))
                    })
                    .collect(),
            ),
        ];

        for policy in &policies {
            for task in ALL_TASKS {
                for secrets in [vec![], vec![SecretKind::ApiKey]] {
                    let decision = policy.evaluate(&request(
                        Locality::Remote,
                        Sensitivity::Secret,
                        task,
                        secrets.clone(),
                    ));
                    assert_eq!(
                        decision,
                        EgressDecision::Deny {
                            reason: DenyReason::SecretContent
                        },
                        "Secret escaped: policy={:?} task={task:?} secrets={secrets:?}",
                        policy.policy_id()
                    );
                }
            }
        }
    }

    /// The full decision table for the non-Secret cases.
    #[test]
    fn the_decision_table_is_complete_and_ordered() {
        let permissive = StandardPolicy::enabling(vec![("acme".to_owned(), TaskKind::Extraction)]);

        // Local is always allowed, at every sensitivity.
        for s in ALL_SENSITIVITIES {
            assert_eq!(
                permissive.evaluate(&request(Locality::Local, s, TaskKind::Extraction, vec![])),
                EgressDecision::Allow,
                "local should be allowed at {s:?}"
            );
        }

        // Remote, permitted task, no secrets: redacted.
        assert!(matches!(
            permissive.evaluate(&request(
                Locality::Remote,
                Sensitivity::Private,
                TaskKind::Extraction,
                vec![]
            )),
            EgressDecision::AllowRedacted(_)
        ));

        // Remote, task not on the list: denied, even though the provider is.
        assert_eq!(
            permissive.evaluate(&request(
                Locality::Remote,
                Sensitivity::Private,
                TaskKind::Conversation,
                vec![]
            )),
            EgressDecision::Deny {
                reason: DenyReason::ProviderNotEnabledForTask
            }
        );

        // A detected secret denies even a permitted task.
        assert_eq!(
            permissive.evaluate(&request(
                Locality::Remote,
                Sensitivity::Public,
                TaskKind::Extraction,
                vec![SecretKind::NostrSecretKey]
            )),
            EgressDecision::Deny {
                reason: DenyReason::SecretDetected
            }
        );
    }

    /// The default must be off. A build nobody configured cannot egress.
    #[test]
    fn the_default_policy_denies_all_remote_traffic() {
        let policy = StandardPolicy::default();
        for s in ALL_SENSITIVITIES {
            for task in ALL_TASKS {
                let decision = policy.evaluate(&request(Locality::Remote, s, task, vec![]));
                assert!(
                    matches!(decision, EgressDecision::Deny { .. }),
                    "default policy allowed {s:?}/{task:?}"
                );
            }
        }
        assert_eq!(policy.policy_id(), "deny-all/v1");
    }

    /// Enabling a provider for one task must not enable it for another.
    ///
    /// Otherwise "let it answer my questions" quietly becomes "let it read the
    /// whole corpus for extraction".
    #[test]
    fn enabling_one_task_does_not_enable_the_others() {
        let policy = StandardPolicy::enabling(vec![("acme".to_owned(), TaskKind::Conversation)]);
        assert!(matches!(
            policy.evaluate(&request(
                Locality::Remote,
                Sensitivity::Private,
                TaskKind::Conversation,
                vec![]
            )),
            EgressDecision::AllowRedacted(_)
        ));
        for other in ALL_TASKS.iter().filter(|t| **t != TaskKind::Conversation) {
            assert_eq!(
                policy.evaluate(&request(
                    Locality::Remote,
                    Sensitivity::Private,
                    *other,
                    vec![]
                )),
                EgressDecision::Deny {
                    reason: DenyReason::ProviderNotEnabledForTask
                },
                "task {other:?} leaked through"
            );
        }
    }

    /// A different provider name must not inherit another's permission.
    #[test]
    fn permission_does_not_transfer_between_providers() {
        let policy = StandardPolicy::enabling(vec![("acme".to_owned(), TaskKind::Extraction)]);
        let mut req = request(
            Locality::Remote,
            Sensitivity::Private,
            TaskKind::Extraction,
            vec![],
        );
        req.provider = "someone-else".to_owned();
        assert_eq!(
            policy.evaluate(&req),
            EgressDecision::Deny {
                reason: DenyReason::ProviderNotEnabledForTask
            }
        );
    }
}
