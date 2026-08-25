//! The egress gate: what may leave the device, and the record that it did.
//!
//! Rules, in order (SPEC §11.2):
//!
//! 1. [`Sensitivity::Secret`] → **Deny**, unconditionally, no override.
//! 2. Remote provider not explicitly enabled for this task → **Deny**.
//! 3. Real entity names → replaced with stable pseudonyms. The mapping stays on
//!    the device.
//! 4. Detected secrets → **Deny**, with the finding surfaced to the user rather
//!    than silently redacted.
//! 5. Otherwise → **AllowRedacted**, carrying the plan that will be applied.
//!
//! Rule 4 is worth dwelling on. Silently stripping a detected API key would be
//! more convenient and is the wrong call: the user needs to know a credential
//! was sitting in their corpus, and a redactor that quietly cleans up teaches
//! them nothing.

use ghostr_core::ids::EntityId;
use ghostr_core::sensitivity::Sensitivity;
use ghostr_core::time::Timestamp;
use serde::{Deserialize, Serialize};

use crate::model::TaskKind;
use crate::redact::RedactionPlan;

/// Decides whether a payload may leave the device.
///
/// Synchronous and pure. A policy that could await is a policy that could
/// consult the network to decide whether to use the network.
pub trait EgressPolicy: Send + Sync {
    /// Evaluates one request.
    fn evaluate(&self, request: &EgressRequest) -> EgressDecision;

    /// A stable identifier for this policy, recorded in the log.
    ///
    /// So an audit can distinguish "allowed under the strict policy" from
    /// "allowed after the user loosened it", which is the difference that
    /// matters when reading the log months later.
    fn policy_id(&self) -> &str;
}

/// What the gate is being asked about.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EgressRequest {
    /// Where it would go.
    pub provider: String,
    /// Whether that destination is local or remote.
    pub locality: crate::model::Locality,
    /// What the request is for.
    pub task: TaskKind,
    /// Highest sensitivity of any input. The maximum, never the average.
    pub max_sensitivity: Sensitivity,
    /// Entities named in the payload, which will become pseudonyms.
    pub entities: Vec<EntityId>,
    /// Payload size before redaction.
    pub payload_bytes: u32,
    /// Secrets the detector found.
    ///
    /// Non-empty means deny. Kinds only — a detector that put the secret it
    /// found into the decision record would be the leak it exists to prevent.
    pub detected_secrets: Vec<SecretKind>,
}

/// What the gate decided.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "decision")]
pub enum EgressDecision {
    /// May leave as-is. Only ever for local destinations.
    Allow,
    /// May leave once the plan is applied.
    AllowRedacted(RedactionPlan),
    /// May not leave.
    Deny {
        /// Why.
        reason: DenyReason,
    },
}

/// Why the gate refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, thiserror::Error)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum DenyReason {
    /// `Secret` content was routed at a remote provider.
    ///
    /// There is no configuration that allows this and there must never be one:
    /// a setting that relaxes it is a setting that will eventually be on.
    #[error("content is marked Secret and may never leave the device")]
    SecretContent,
    /// The provider is not enabled for this task.
    #[error("provider is not enabled for this task")]
    ProviderNotEnabledForTask,
    /// A credential or identifier was detected in the payload.
    #[error("payload contains a detected secret")]
    SecretDetected,
    /// Entity pseudonymisation could not be applied.
    ///
    /// Fails closed. A payload that should have carried "Person A" and instead
    /// carries a real name is the exact failure the pseudonym layer exists to
    /// prevent.
    #[error("entity pseudonymisation failed")]
    PseudonymisationFailed,
    /// The user has switched egress off entirely.
    #[error("egress is disabled by user configuration")]
    UserDisabled,
}

/// Append-only audit record of every egress decision.
///
/// Both allows *and* denies. A log of only the allows cannot show that the
/// system refused anything, and a privacy claim a user cannot audit is a
/// promise rather than a property (SPEC I5).
#[async_trait::async_trait]
pub trait EgressLog: Send + Sync {
    /// Records a decision.
    ///
    /// Callers must treat a failure here as fatal to the request. Proceeding
    /// with an unrecorded egress is precisely what the user was told could not
    /// happen.
    ///
    /// # Errors
    ///
    /// Returns an error if the record cannot be durably written.
    async fn record(&self, entry: EgressEntry) -> crate::Result<()>;

    /// Entries since an instant, oldest first. Backs `gst egress log`.
    ///
    /// # Errors
    ///
    /// Returns an error if the read fails.
    async fn since(&self, from: Timestamp) -> crate::Result<Vec<EgressEntry>>;

    /// Totals over a window, for a summary view.
    ///
    /// # Errors
    ///
    /// Returns an error if the read fails.
    async fn summary(&self, from: Timestamp, to: Timestamp) -> crate::Result<EgressSummary>;
}

/// One line in the egress log.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EgressEntry {
    /// When.
    pub at: Timestamp,
    /// Where to.
    pub provider: String,
    /// What for.
    pub task: TaskKind,
    /// What the gate said.
    pub decision: EgressDecision,
    /// Which policy said it.
    pub policy_id: String,
    /// Bytes actually transmitted. Zero for a deny.
    pub bytes_sent: u32,
    /// Digest of the exact bytes sent, after redaction.
    ///
    /// The payload itself is never stored — that would recreate the corpus in
    /// the audit log. The digest lets a user prove *what* was sent if they kept
    /// the redacted copy, without the log itself becoming a second corpus.
    pub payload_digest: Option<ghostr_core::hash::Hash32>,
    /// How many entity names were pseudonymised.
    pub entities_pseudonymised: u32,
}

/// Totals over a window.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct EgressSummary {
    /// Requests allowed.
    pub allowed: u32,
    /// Requests denied.
    pub denied: u32,
    /// Total bytes transmitted.
    pub bytes_sent: u64,
    /// Requests that never left because the destination was local.
    pub local_only: u32,
}

/// What kind of secret a detector found.
///
/// Kinds only, never values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum SecretKind {
    /// An API key or bearer token.
    ApiKey,
    /// A private key in any armoured form.
    PrivateKey,
    /// A payment card number.
    PaymentCard,
    /// A national identifier.
    NationalId,
    /// A password-shaped assignment.
    Password,
    /// A nostr `nsec`.
    ///
    /// Called out separately because it is the one whose leak is unrecoverable
    /// (THREAT_MODEL §T5).
    NostrSecretKey,
}
