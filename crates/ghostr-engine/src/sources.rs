//! Configured sources: adding, listing, and pulling from them.
//!
//! The engine is the only place that knows which adapters are real, which is
//! why dispatch lives here rather than in `ghostr-ingest` (ARCHITECTURE §3).

use ghostr_core::ids::SourceId;
use ghostr_core::sensitivity::{Sensitivity, TrustLevel};
use ghostr_core::source::{LogSchema, SourceKindTag, SyncCursor};
use ghostr_store::sqlite::StoredSource;

use crate::engine::Engine;

/// What a user is about to add.
///
/// Kept separate from [`ghostr_core::source::SourceKind`] because adding is a
/// decision, and the decision needs the two things the type does not carry: how
/// the content will be trusted, and whether pulling reaches the network.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewSource {
    /// Which adapter.
    pub kind: SourceKindTag,
    /// Where it reads from. A path for every kind M1 supports.
    pub location: String,
    /// For a structured log, which schema its rows conform to.
    pub schema: Option<LogSchema>,
}

/// What adding a source will mean, shown before it is added.
///
/// Surfacing "this is somebody else's text" and "this will talk to the
/// internet" at the moment of the decision, rather than leaving them to be
/// discovered afterwards (THREAT_MODEL §T7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourcePlan {
    /// The source as it will be stored.
    pub kind_tag: String,
    /// Its location.
    pub location: String,
    /// How its content will be trusted.
    pub trust: TrustLevel,
    /// The sensitivity floor its memories will carry.
    pub sensitivity: Sensitivity,
    /// Whether pulling reaches the network.
    pub touches_network: bool,
}

/// Works out what adding this source would mean, without adding it.
///
/// # Errors
///
/// Returns [`Error::Config`](crate::Error::Config) if the kind has no adapter in
/// this build, or if a structured log was named without a schema.
pub fn plan(new: &NewSource) -> crate::Result<SourcePlan> {
    let (kind_tag, trust, sensitivity, touches_network) = match new.kind {
        SourceKindTag::MarkdownVault => (
            ghostr_ingest::markdown::KIND_TAG,
            ghostr_ingest::markdown::default_trust(),
            Sensitivity::Private,
            false,
        ),
        SourceKindTag::Journal => (
            ghostr_ingest::journal::KIND_TAG,
            ghostr_ingest::journal::default_trust(),
            Sensitivity::Private,
            false,
        ),
        SourceKindTag::StructuredLog => {
            let Some(schema) = new.schema else {
                return Err(crate::Error::Config {
                    detail: "a structured log needs --schema".to_owned(),
                });
            };
            (
                ghostr_ingest::structlog::KIND_TAG,
                ghostr_ingest::structlog::default_trust(),
                ghostr_ingest::structlog::suggested_sensitivity(schema),
                false,
            )
        }
        // Networked adapters arrive with M2. Naming one is a configuration
        // error rather than a silently skipped sync: a source that stops
        // producing memories without saying so is the worst failure mode a
        // memory system has.
        _ => {
            return Err(crate::Error::Config {
                detail: "no adapter for that source kind in this build".to_owned(),
            });
        }
    };
    Ok(SourcePlan {
        kind_tag: kind_tag.to_owned(),
        location: new.location.clone(),
        trust,
        sensitivity,
        touches_network,
    })
}

/// Adds a source, or returns the id of the one already configured this way.
///
/// # Errors
///
/// Returns [`Error::Config`](crate::Error::Config) if the source cannot be
/// planned, or [`Error::Ingest`](crate::Error::Ingest) if its location does not
/// exist — a typo should fail here, not at 23:59.
pub fn add(engine: &Engine, new: &NewSource) -> crate::Result<(SourceId, SourcePlan)> {
    let plan = plan(new)?;

    // The journal has no location to check: its entries live in the store.
    if new.kind != SourceKindTag::Journal {
        let path = std::path::Path::new(&new.location);
        if !path.exists() {
            return Err(crate::Error::Config {
                detail: "that path does not exist".to_owned(),
            });
        }
    }

    let dek = engine.dek()?;
    let mut random = [0u8; 10];
    engine.rng().fill(&mut random);
    let config = config_json(new)?;
    let id = engine.store().upsert_source_with(
        dek,
        &ghostr_store::sqlite::NewSourceRow {
            id: SourceId::new(engine.now().utc_millis().unsigned_abs(), random),
            kind_tag: &plan.kind_tag,
            config: &config,
            trust: plan.trust,
            sensitivity: plan.sensitivity,
        },
        engine.nonce(),
    )?;
    Ok((id, plan))
}

/// Every configured source.
///
/// # Errors
///
/// Returns [`Error::Store`](crate::Error::Store) if the read fails.
pub fn list(engine: &Engine) -> crate::Result<Vec<StoredSource>> {
    Ok(engine.store().all_sources(engine.dek()?)?)
}

/// What one sync produced.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SyncReport {
    /// Sources pulled.
    pub sources: u32,
    /// Memories added.
    pub ingested: u32,
    /// Records already present, skipped by digest.
    pub skipped: u32,
    /// Records that could not be parsed.
    pub unparseable: u32,
    /// Sources whose location could not be read.
    ///
    /// Counted rather than fatal: one unplugged drive should not stop the other
    /// sources from syncing.
    pub unreachable: u32,
}

/// Pulls from every enabled source, or from one named source.
///
/// # Errors
///
/// Returns [`Error::Store`](crate::Error::Store) if a write fails. An
/// unreachable *source* is counted, not returned.
pub fn sync(engine: &Engine, only: Option<SourceId>) -> crate::Result<SyncReport> {
    let dek = engine.dek()?;
    let mut report = SyncReport::default();

    for source in engine.store().all_sources(dek)? {
        if !source.enabled || only.is_some_and(|id| id != source.id) {
            continue;
        }
        report.sources += 1;
        let memories = match pull(engine, &source) {
            Ok(memories) => memories,
            Err(_) => {
                report.unreachable += 1;
                continue;
            }
        };
        for memory in &memories {
            if engine
                .store()
                .has_raw_hash(source.id, memory.provenance.raw_hash)?
            {
                report.skipped += 1;
                continue;
            }
            match engine.store().put_memory(dek, memory, engine.nonce()) {
                Ok(()) => report.ingested += 1,
                Err(ghostr_store::Error::AppendOnlyViolation { .. }) => report.skipped += 1,
                Err(e) => return Err(e.into()),
            }
        }
        // The cursor advances only over what was actually stored, so a crash
        // mid-sync loses work rather than skipping a span.
        engine
            .store()
            .set_source_cursor(source.id, &cursor_json(&memories))?;
    }
    Ok(report)
}

/// Reads every memory a source currently offers.
fn pull(engine: &Engine, source: &StoredSource) -> crate::Result<Vec<ghostr_core::memory::Memory>> {
    let location = location_of(&source.config);
    let path = std::path::Path::new(&location);

    if source.kind_tag == ghostr_ingest::markdown::KIND_TAG {
        let notes = ghostr_ingest::markdown::scan_vault(path, source.id)?;
        return Ok(notes
            .iter()
            .map(|n| ghostr_ingest::markdown::to_memory(n, source.id, engine.clock(), engine.rng()))
            .collect());
    }
    if source.kind_tag == ghostr_ingest::journal::KIND_TAG {
        // A push source: entries are made with `ghostr journal`, so there is
        // nothing to poll.
        return Ok(Vec::new());
    }
    if source.kind_tag == ghostr_ingest::structlog::KIND_TAG {
        let schema = schema_of(&source.config).unwrap_or(LogSchema::Health);
        let scanned = ghostr_ingest::structlog::scan(path, source.id)?;
        let mut out = Vec::new();
        for row in &scanned.rows {
            if let Ok(memory) = ghostr_ingest::structlog::to_memory(
                row,
                schema,
                source.id,
                engine.clock(),
                engine.rng(),
            ) {
                out.push(memory);
            }
        }
        return Ok(out);
    }
    Err(crate::Error::Ingest(ghostr_ingest::Error::NoAdapter {
        kind: source.kind_tag.clone(),
    }))
}

/// A source's stored configuration, as JSON.
fn config_json(new: &NewSource) -> crate::Result<String> {
    let mut map = serde_json::Map::new();
    map.insert(
        "location".to_owned(),
        serde_json::Value::String(new.location.clone()),
    );
    if let Some(schema) = new.schema {
        map.insert(
            "schema".to_owned(),
            serde_json::to_value(schema).map_err(|_| crate::Error::Config {
                detail: "schema is not serialisable".to_owned(),
            })?,
        );
    }
    serde_json::to_string(&serde_json::Value::Object(map)).map_err(|_| crate::Error::Config {
        detail: "source configuration is not serialisable".to_owned(),
    })
}

/// Reads the location out of a stored configuration.
fn location_of(config: &str) -> String {
    serde_json::from_str::<serde_json::Value>(config)
        .ok()
        .and_then(|v| v.get("location")?.as_str().map(ToOwned::to_owned))
        // M0 stored the bare path rather than JSON. Falling back to it keeps a
        // vault created then working now.
        .unwrap_or_else(|| config.to_owned())
}

/// Reads the log schema out of a stored configuration.
fn schema_of(config: &str) -> Option<LogSchema> {
    let value: serde_json::Value = serde_json::from_str(config).ok()?;
    serde_json::from_value(value.get("schema")?.clone()).ok()
}

/// The cursor to record after a pull.
///
/// Sits *on* the newest memory rather than past it, so records sharing that
/// instant cannot be skipped. The repeat is absorbed by the store's digest
/// index; a skipped record would be lost for good.
fn cursor_json(memories: &[ghostr_core::memory::Memory]) -> String {
    let newest = memories
        .iter()
        .filter_map(|m| m.occurred_at)
        .max_by_key(ghostr_core::time::Timestamp::utc_millis);
    let cursor = newest.map_or(SyncCursor::Start, SyncCursor::Timestamp);
    serde_json::to_string(&cursor).unwrap_or_else(|_| "{}".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_structured_log_without_a_schema_is_refused() {
        let new = NewSource {
            kind: SourceKindTag::StructuredLog,
            location: "/h.jsonl".to_owned(),
            schema: None,
        };
        assert!(plan(&new).is_err());
    }

    /// Health logs suggest `Secret`, which is what stops them ever reaching a
    /// remote provider.
    #[test]
    fn a_health_log_plans_as_secret() {
        let new = NewSource {
            kind: SourceKindTag::StructuredLog,
            location: "/h.jsonl".to_owned(),
            schema: Some(LogSchema::Health),
        };
        let p = plan(&new).expect("plan");
        assert_eq!(p.sensitivity, Sensitivity::Secret);
        assert!(!p.sensitivity.may_egress());
        assert!(!p.touches_network);
    }

    /// A step count is not a sentence the user wrote (THREAT_MODEL §T7).
    #[test]
    fn a_structured_log_is_never_a_voice_exemplar() {
        let new = NewSource {
            kind: SourceKindTag::StructuredLog,
            location: "/h.jsonl".to_owned(),
            schema: Some(LogSchema::Media),
        };
        assert!(!plan(&new).expect("plan").trust.may_be_exemplar());
    }

    /// A kind with no adapter fails loudly. A source that stops producing
    /// memories without saying so is the worst failure mode a memory system
    /// has.
    #[test]
    fn a_kind_with_no_adapter_is_a_configuration_error() {
        let new = NewSource {
            kind: SourceKindTag::Rss,
            location: "https://example.invalid/feed".to_owned(),
            schema: None,
        };
        assert!(plan(&new).is_err());
    }

    #[test]
    fn a_configuration_round_trips_through_json() {
        let new = NewSource {
            kind: SourceKindTag::StructuredLog,
            location: "/health.jsonl".to_owned(),
            schema: Some(LogSchema::Places),
        };
        let json = config_json(&new).expect("json");
        assert_eq!(location_of(&json), "/health.jsonl");
        assert_eq!(schema_of(&json), Some(LogSchema::Places));
    }

    /// A vault created by M0 stored the bare path. It must keep working.
    #[test]
    fn a_bare_path_from_an_older_vault_still_reads() {
        assert_eq!(location_of("/home/someone/notes"), "/home/someone/notes");
    }
}
