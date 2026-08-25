//! Wiring a model in, and the audit log it writes through.
//!
//! Compiled only with the `llm` feature. Without it the binary has no model
//! path at all, which makes "works offline with no LLM" checkable with
//! `cargo tree` rather than a claim in a README.
//!
//! This is the composition root's share of the egress boundary: it is where the
//! policy, the audit log, and the redactor are attached to a provider. Nothing
//! outside `ghostr-llm` can construct a remote provider unwrapped, so a remote
//! model reaching a caller has necessarily come through here.

use std::sync::Arc;

use async_trait::async_trait;
use ghostr_core::hash::Hash32;
use ghostr_core::time::Timestamp;
use ghostr_llm::egress::{EgressEntry, EgressLog, EgressSummary};
use ghostr_llm::gate::{GatedModel, LocalModelConfig, RemoteModelConfig};
use ghostr_llm::model::{LanguageModel, TaskKind};
use ghostr_llm::pseudonym::{EntityRedactor, KnownEntity};
use ghostr_llm::redact::{RedactionPlan, Redactor};
use ghostr_store::sqlite::EgressRecord;

use crate::engine::Engine;

/// The store, as the gate's audit log.
///
/// Holds its own connection to the same database rather than borrowing the
/// engine's. The gate needs a `Send + Sync` log and a rusqlite connection is
/// only `Send`, so the alternative would be threading a lock through the
/// engine's every read. SQLite in WAL mode is built for exactly this.
///
/// The append-only guarantee is not this type's to keep: it is a pair of
/// triggers in the schema, so "the record was written and cannot be edited" is
/// a database fact rather than an application promise (SPEC I5).
pub struct StoreEgressLog {
    store: std::sync::Mutex<ghostr_store::sqlite::SqliteStore>,
}

impl core::fmt::Debug for StoreEgressLog {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("StoreEgressLog")
    }
}

impl StoreEgressLog {
    /// Opens a second connection to the vault's database.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Store`](crate::Error::Store) if the database cannot be
    /// opened.
    pub fn open(dir: &std::path::Path) -> crate::Result<Self> {
        Ok(Self {
            store: std::sync::Mutex::new(ghostr_store::sqlite::SqliteStore::open(dir)?),
        })
    }

    /// Runs `f` against the connection.
    ///
    /// A poisoned lock is reported as the log being unavailable, which is fatal
    /// to the request that hit it: an egress that could not be recorded is the
    /// thing the user was told could not happen (I5).
    fn with<T>(
        &self,
        f: impl FnOnce(&ghostr_store::sqlite::SqliteStore) -> ghostr_store::Result<T>,
    ) -> ghostr_llm::Result<T> {
        let guard = self
            .store
            .lock()
            .map_err(|_| ghostr_llm::Error::EgressLogUnavailable)?;
        f(&guard).map_err(|_| ghostr_llm::Error::EgressLogUnavailable)
    }
}

#[async_trait]
impl EgressLog for StoreEgressLog {
    async fn record(&self, entry: EgressEntry) -> ghostr_llm::Result<()> {
        self.with(|store| store.append_egress(&to_record(&entry)))
    }

    async fn since(&self, from: Timestamp) -> ghostr_llm::Result<Vec<EgressEntry>> {
        let records = self.with(|store| store.egress_since(from))?;
        Ok(records.iter().map(from_record).collect())
    }

    async fn summary(&self, from: Timestamp, to: Timestamp) -> ghostr_llm::Result<EgressSummary> {
        let records = self.with(|store| store.egress_since(from))?;
        let mut summary = EgressSummary::default();
        for record in &records {
            if record.at.utc_millis() > to.utc_millis() {
                continue;
            }
            if record.decision.starts_with("allow") {
                summary.allowed += 1;
                summary.bytes_sent += u64::from(record.bytes_sent);
            } else {
                summary.denied += 1;
            }
        }
        Ok(summary)
    }
}

/// Converts a gate entry into a stored row.
fn to_record(entry: &EgressEntry) -> EgressRecord {
    EgressRecord {
        at: entry.at,
        provider: entry.provider.clone(),
        task: task_tag(entry.task).to_owned(),
        decision: decision_tag(&entry.decision),
        deny_reason: deny_reason(&entry.decision),
        policy_id: entry.policy_id.clone(),
        bytes_sent: entry.bytes_sent,
        payload_digest: entry.payload_digest.map(|d| d.to_hex()),
        entities: entry.entities_pseudonymised,
    }
}

/// Converts a stored row back into a gate entry.
fn from_record(record: &EgressRecord) -> EgressEntry {
    use ghostr_llm::egress::{DenyReason, EgressDecision};

    let decision = match record.decision.as_str() {
        "allow" => EgressDecision::Allow,
        // The plan itself is not stored — it names entities, which is content —
        // so a redacted allow reads back with an empty plan and the count of
        // what it replaced. The log records that redaction happened and how
        // much, never what was redacted (I8).
        "allow_redacted" => EgressDecision::AllowRedacted(RedactionPlan::default()),
        // Anything else reads as a deny. A row this build does not recognise
        // must not read as an allow: the log's whole job is to be believed, and
        // over-reporting a deny is the direction that fails safe.
        _ => EgressDecision::Deny {
            reason: DenyReason::UserDisabled,
        },
    };
    EgressEntry {
        at: record.at,
        provider: record.provider.clone(),
        task: parse_task(&record.task),
        decision,
        policy_id: record.policy_id.clone(),
        bytes_sent: record.bytes_sent,
        payload_digest: record
            .payload_digest
            .as_deref()
            .and_then(|hex| Hash32::from_hex(hex).ok()),
        entities_pseudonymised: record.entities,
    }
}

/// The stored form of a decision.
fn decision_tag(decision: &ghostr_llm::egress::EgressDecision) -> String {
    use ghostr_llm::egress::EgressDecision;

    match decision {
        EgressDecision::Allow => "allow",
        EgressDecision::AllowRedacted(_) => "allow_redacted",
        EgressDecision::Deny { .. } => "deny",
    }
    .to_owned()
}

/// The stored reason for a deny, if it was one.
fn deny_reason(decision: &ghostr_llm::egress::EgressDecision) -> Option<String> {
    use ghostr_llm::egress::EgressDecision;

    match decision {
        EgressDecision::Deny { reason } => Some(format!("{reason}")),
        EgressDecision::Allow | EgressDecision::AllowRedacted(_) => None,
    }
}

/// The stored form of a task.
const fn task_tag(task: TaskKind) -> &'static str {
    match task {
        TaskKind::Extraction => "extraction",
        TaskKind::Summarization => "summarization",
        TaskKind::Distillation => "distillation",
        TaskKind::QuestGeneration => "quest_generation",
        TaskKind::Conversation => "conversation",
        TaskKind::Embedding => "embedding",
        _ => "unknown",
    }
}

/// Reads a stored task tag.
fn parse_task(tag: &str) -> TaskKind {
    match tag {
        "extraction" => TaskKind::Extraction,
        "summarization" => TaskKind::Summarization,
        "distillation" => TaskKind::Distillation,
        "quest_generation" => TaskKind::QuestGeneration,
        "embedding" => TaskKind::Embedding,
        _ => TaskKind::Conversation,
    }
}

/// Builds the egress policy this vault is configured with.
///
/// Off unless the vault says otherwise, and off entirely if `egress_enabled` is
/// false however long the allow list is. The two switches are separate so
/// "turn it all off" does not mean editing a list (SPEC §11.2).
#[must_use]
pub fn policy_from(config: &crate::config::Config) -> ghostr_llm::StandardPolicy {
    if !config.egress_enabled {
        return ghostr_llm::StandardPolicy::deny_all();
    }
    let pairs = config
        .egress_allow
        .iter()
        .filter_map(|entry| {
            let (provider, task) = entry.split_once(':')?;
            // An unparseable task is dropped rather than guessed at. Guessing
            // here would enable a provider for something the user did not name.
            Some((provider.trim().to_owned(), known_task(task.trim())?))
        })
        .collect();
    ghostr_llm::StandardPolicy::enabling(pairs)
}

/// Reads a task name from configuration, refusing anything unrecognised.
fn known_task(name: &str) -> Option<TaskKind> {
    match name {
        "extraction" => Some(TaskKind::Extraction),
        "summarization" => Some(TaskKind::Summarization),
        "distillation" => Some(TaskKind::Distillation),
        "quest_generation" => Some(TaskKind::QuestGeneration),
        "conversation" => Some(TaskKind::Conversation),
        // Embedding is deliberately absent: there is no remote embedding path
        // and configuration must not be able to invent one (SPEC Q13).
        _ => None,
    }
}

/// Builds a redactor over every entity the vault knows.
///
/// # Errors
///
/// Returns [`Error::Store`](crate::Error::Store) if the entity table cannot be
/// read. Failing rather than degrading to an empty redactor is deliberate: an
/// empty redactor sends real names.
pub fn redactor(engine: &Engine) -> crate::Result<EntityRedactor> {
    let known = engine
        .store()
        .all_entities(engine.dek()?)?
        .into_iter()
        .map(|e| KnownEntity {
            id: e.id,
            name: e.name,
            pseudonym: e.pseudonym,
        })
        .collect();
    Ok(EntityRedactor::new(known))
}

/// Builds the configured local model.
///
/// # Errors
///
/// Returns [`Error::Llm`](crate::Error::Llm) if no local provider is compiled
/// into this build.
pub fn local_model(config: LocalModelConfig) -> crate::Result<Arc<dyn LanguageModel>> {
    Ok(ghostr_llm::gate::local(config)?)
}

/// Builds the configured remote model, wrapped in its gate.
///
/// The only way this crate obtains a remote model, and it cannot be otherwise:
/// the providers are private to `ghostr-llm` and `remote` is the only
/// constructor that reaches them.
///
/// # Errors
///
/// Returns [`Error::Llm`](crate::Error::Llm) if the provider is not compiled in,
/// or [`Error::Store`](crate::Error::Store) if the redactor cannot be built.
pub fn remote_model(engine: &Engine, config: RemoteModelConfig) -> crate::Result<GatedModel> {
    let log: Arc<dyn EgressLog> = Arc::new(StoreEgressLog::open(engine.dir())?);
    let policy: Arc<dyn ghostr_llm::egress::EgressPolicy> =
        Arc::new(policy_from(&crate::config::Config::load(engine.dir())?));
    let redactor: Arc<dyn Redactor> = Arc::new(redactor(engine)?);
    Ok(ghostr_llm::gate::remote(config, policy, log, redactor)?)
}

#[cfg(test)]
mod tests {
    use ghostr_llm::egress::{DenyReason, EgressDecision};

    use super::*;

    fn entry(decision: EgressDecision) -> EgressEntry {
        EgressEntry {
            at: Timestamp::new(1_700_000_000_000, 0),
            provider: "acme".to_owned(),
            task: TaskKind::Summarization,
            decision,
            policy_id: "standard-v1".to_owned(),
            bytes_sent: 128,
            payload_digest: Some(ghostr_core::hash::tagged_hash(
                ghostr_core::hash::Tag::MetaLeaf,
                b"payload",
            )),
            entities_pseudonymised: 2,
        }
    }

    #[test]
    fn an_entry_round_trips_through_the_store_shape() {
        let original = entry(EgressDecision::AllowRedacted(RedactionPlan::default()));
        let back = from_record(&to_record(&original));
        assert_eq!(back.provider, original.provider);
        assert_eq!(back.task, original.task);
        assert_eq!(back.decision, original.decision);
        assert_eq!(back.payload_digest, original.payload_digest);
        assert_eq!(back.entities_pseudonymised, 2);
    }

    /// The log's whole job is to be believed. A row this build cannot read must
    /// not read as an allow.
    #[test]
    fn an_unrecognised_decision_reads_as_a_deny() {
        let mut record = to_record(&entry(EgressDecision::Allow));
        record.decision = "something_from_the_future".to_owned();
        assert!(matches!(
            from_record(&record).decision,
            EgressDecision::Deny { .. }
        ));
    }

    #[test]
    fn a_deny_records_its_reason() {
        let record = to_record(&entry(EgressDecision::Deny {
            reason: DenyReason::SecretContent,
        }));
        assert_eq!(record.decision, "deny");
        assert!(record.deny_reason.is_some());
        assert_eq!(record.bytes_sent, 128);
    }

    /// The reason is a category, never the content that triggered it (I8).
    #[test]
    fn a_deny_reason_never_carries_content() {
        let record = to_record(&entry(EgressDecision::Deny {
            reason: DenyReason::SecretDetected,
        }));
        let reason = record.deny_reason.expect("a reason");
        assert!(!reason.contains("sk-"));
    }

    /// The master switch wins, however long the allow list is.
    #[test]
    fn egress_disabled_denies_regardless_of_the_allow_list() {
        let config = crate::config::Config {
            egress_enabled: false,
            egress_allow: vec!["anthropic:summarization".to_owned()],
            ..crate::config::Config::default()
        };
        let policy = policy_from(&config);
        assert_eq!(policy, ghostr_llm::StandardPolicy::deny_all());
    }

    /// Configuration must not be able to invent a remote embedding path
    /// (SPEC Q13).
    #[test]
    fn embedding_can_never_be_enabled_from_configuration() {
        assert!(known_task("embedding").is_none());
        assert_eq!(known_task("summarization"), Some(TaskKind::Summarization));
    }

    /// An unrecognised task is dropped, not guessed at: guessing would enable a
    /// provider for something the user did not name.
    #[test]
    fn an_unknown_task_name_is_dropped() {
        assert!(known_task("everything").is_none());
    }

    #[test]
    fn every_task_tag_round_trips() {
        for task in [
            TaskKind::Extraction,
            TaskKind::Summarization,
            TaskKind::Distillation,
            TaskKind::QuestGeneration,
            TaskKind::Conversation,
            TaskKind::Embedding,
        ] {
            assert_eq!(parse_task(task_tag(task)), task);
        }
    }
}
