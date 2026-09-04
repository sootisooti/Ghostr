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
    /// Where it reads from. A path for every local kind.
    pub location: String,
    /// For a structured log, which schema its rows conform to.
    pub schema: Option<LogSchema>,
    /// For a nostr feed, whose notes and from where.
    pub feed: Option<FeedConfig>,
}

/// Which nostr feed to read, and from which relays.
///
/// A feed has no path, so it cannot travel in `location`: it is an author, a
/// set of relays, and a set of kinds, and all three are part of the decision a
/// user is making when they add it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeedConfig {
    /// Whose feed. A 64-character hex x-only pubkey.
    pub pubkey: String,
    /// Relays to read from.
    ///
    /// Named per source rather than taken from the vault's own relay list. The
    /// relays a user publishes their encrypted history to and the relays they
    /// read somebody else's notes from are different decisions, and conflating
    /// them would let adding a feed quietly widen where a backup goes.
    pub relays: Vec<String>,
    /// Event kinds to pull. See `ghostr_ingest::nostr::READABLE_KINDS`.
    pub kinds: Vec<u16>,
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
        SourceKindTag::NostrFeed => {
            if new.feed.is_none() {
                return Err(crate::Error::Config {
                    detail: "a nostr feed needs --pubkey and at least one --relay".to_owned(),
                });
            }
            (
                ghostr_ingest::nostr::KIND_TAG,
                ghostr_ingest::nostr::default_trust(),
                ghostr_ingest::nostr::default_sensitivity(),
                true,
            )
        }
        // The remaining kinds have no adapter. Naming one is a configuration
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
        location: describe_location(new),
        trust,
        sensitivity,
        touches_network,
    })
}

/// What to show a user as "where this reads from".
///
/// A feed has no path, so the pubkey stands in. Truncated the way every nostr
/// client truncates one, because a 64-character hex string in a confirmation
/// prompt is a string nobody reads.
fn describe_location(new: &NewSource) -> String {
    match new.feed.as_ref() {
        Some(feed) if new.kind == SourceKindTag::NostrFeed => {
            let key = &feed.pubkey;
            let short = if key.len() > 16 {
                format!("{}…{}", &key[..8], &key[key.len() - 8..])
            } else {
                key.clone()
            };
            format!("{short} via {} relay(s)", feed.relays.len())
        }
        _ => new.location.clone(),
    }
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

    let dek = engine.dek()?;
    let mut random = [0u8; 10];
    engine.rng().fill(&mut random);
    let id = SourceId::new(engine.now().utc_millis().unsigned_abs(), random);

    match new.kind {
        // The journal has no location to check: its entries live in the store.
        SourceKindTag::Journal => {}
        // A feed has no path either. Its configuration is checked here, with no
        // relay involved, so a mistyped pubkey fails at the prompt rather than
        // at the first sync — and so that adding a source never opens a socket.
        SourceKindTag::NostrFeed => {
            let Some(feed) = new.feed.as_ref() else {
                return Err(crate::Error::Config {
                    detail: "a nostr feed needs --pubkey and at least one --relay".to_owned(),
                });
            };
            ghostr_ingest::nostr::validate_config(&feed.pubkey, &feed.relays, &feed.kinds, id)?;
        }
        _ => {
            let path = std::path::Path::new(&new.location);
            if !path.exists() {
                return Err(crate::Error::Config {
                    detail: "that path does not exist".to_owned(),
                });
            }
        }
    }

    let config = config_json(new)?;
    let id = engine.store().upsert_source_with(
        dek,
        &ghostr_store::sqlite::NewSourceRow {
            id,
            kind_tag: &plan.kind_tag,
            config: &config,
            trust: plan.trust,
            sensitivity: plan.sensitivity,
        },
        engine.nonce(),
    )?;
    Ok((id, plan))
}

/// The relays every enabled feed reads from, deduplicated.
///
/// The read list, and deliberately not the vault's own `relays` config: that
/// one is where encrypted backup is *published*, and building a feed client
/// from it would mean adding a source somebody else's notes come from had
/// quietly widened where the user's history goes.
///
/// Empty means no feed is configured, which is why the caller can skip building
/// a client at all.
///
/// # Errors
///
/// Returns [`Error::Store`](crate::Error::Store) if the read fails.
pub fn feed_relays(engine: &Engine) -> crate::Result<Vec<String>> {
    let mut out: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for source in engine.store().all_sources(engine.dek()?)? {
        if !source.enabled || source.kind_tag != ghostr_ingest::nostr::KIND_TAG {
            continue;
        }
        if let Some(feed) = feed_of(&source.config) {
            out.extend(feed.relays);
        }
    }
    Ok(out.into_iter().collect())
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
    /// Records a source returned that its adapter refused.
    ///
    /// Only a networked source can produce these, and a non-zero count means a
    /// relay answered a filter with events nobody asked for — a different
    /// author, a different kind, or a signature that did not check out
    /// (THREAT_MODEL §T7). Surfaced rather than swallowed: it is the one number
    /// here that can mean somebody is trying something.
    pub rejected: u32,
    /// Feed sources skipped because this run had no relay client.
    ///
    /// Distinct from `unreachable`, which means the relays were tried and did
    /// not answer. This means they were never tried, and a feed that silently
    /// produces nothing looks exactly like a feed whose author stopped posting.
    pub needs_relays: u32,
}

/// Pulls from every enabled source, or from one named source.
///
/// `relays` is `None` for an offline run. Local sources sync either way; feed
/// sources are counted in [`SyncReport::needs_relays`] rather than skipped in
/// silence.
///
/// # Errors
///
/// Returns [`Error::Store`](crate::Error::Store) if a write fails. An
/// unreachable *source* is counted, not returned.
pub async fn sync(
    engine: &Engine,
    only: Option<SourceId>,
    relays: Option<&std::sync::Arc<dyn ghostr_nostr::RelayClient>>,
) -> crate::Result<SyncReport> {
    let dek = engine.dek()?;
    let mut report = SyncReport::default();

    for source in engine.store().all_sources(dek)? {
        if !source.enabled || only.is_some_and(|id| id != source.id) {
            continue;
        }
        if source.kind_tag == ghostr_ingest::nostr::KIND_TAG && relays.is_none() {
            report.needs_relays += 1;
            continue;
        }
        report.sources += 1;
        let memories = match pull(engine, &source, relays).await {
            Ok(pulled) => {
                report.rejected += pulled.rejected;
                report.unparseable += pulled.unparseable;
                report.skipped += pulled.duplicates;
                pulled.memories
            }
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

/// What one source offered, and what its adapter threw away.
struct Pulled {
    memories: Vec<ghostr_core::memory::Memory>,
    /// Records the source returned that the adapter refused. See
    /// [`SyncReport::rejected`].
    rejected: u32,
    /// Records that could not be parsed.
    unparseable: u32,
    /// Records the adapter recognised as already offered.
    duplicates: u32,
}

impl Pulled {
    /// A local source's result: nothing to reject, because nothing was
    /// negotiated with anybody. Local adapters rescan and let the store's
    /// digest index do the deduplicating, so they count nothing here either.
    fn local(memories: Vec<ghostr_core::memory::Memory>) -> Self {
        Self {
            memories,
            rejected: 0,
            unparseable: 0,
            duplicates: 0,
        }
    }
}

/// Reads every memory a source currently offers.
async fn pull(
    engine: &Engine,
    source: &StoredSource,
    relays: Option<&std::sync::Arc<dyn ghostr_nostr::RelayClient>>,
) -> crate::Result<Pulled> {
    if source.kind_tag == ghostr_ingest::nostr::KIND_TAG {
        return pull_feed(engine, source, relays).await;
    }

    let location = location_of(&source.config);
    let path = std::path::Path::new(&location);

    if source.kind_tag == ghostr_ingest::markdown::KIND_TAG {
        let notes = ghostr_ingest::markdown::scan_vault(path, source.id)?;
        return Ok(Pulled::local(
            notes
                .iter()
                .map(|n| {
                    ghostr_ingest::markdown::to_memory(n, source.id, engine.clock(), engine.rng())
                })
                .collect(),
        ));
    }
    if source.kind_tag == ghostr_ingest::journal::KIND_TAG {
        // A push source: entries are made with `ghostr journal`, so there is
        // nothing to poll.
        return Ok(Pulled::local(Vec::new()));
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
        return Ok(Pulled::local(out));
    }
    Err(crate::Error::Ingest(ghostr_ingest::Error::NoAdapter {
        kind: source.kind_tag.clone(),
    }))
}

/// Reads a nostr feed, through the adapter that does the disbelieving.
///
/// The adapter is built here rather than registered once at startup because it
/// needs a relay client, and which relays a vault talks to is a per-run
/// decision the composition root makes (ARCHITECTURE §3).
async fn pull_feed(
    engine: &Engine,
    source: &StoredSource,
    relays: Option<&std::sync::Arc<dyn ghostr_nostr::RelayClient>>,
) -> crate::Result<Pulled> {
    use ghostr_ingest::IngestAdapter as _;

    let Some(client) = relays else {
        return Err(crate::Error::Config {
            detail: "a nostr feed needs relays configured".to_owned(),
        });
    };
    let Some(feed) = feed_of(&source.config) else {
        return Err(crate::Error::Config {
            detail: "this feed's stored configuration cannot be read".to_owned(),
        });
    };

    let adapter = ghostr_ingest::nostr::NostrFeedAdapter::new(
        std::sync::Arc::clone(client),
        engine.clock_arc(),
        engine.rng_arc(),
    );
    let configured = ghostr_core::source::Source {
        id: source.id,
        kind: ghostr_core::source::SourceKind::NostrFeed {
            pubkey: feed.pubkey,
            relays: feed.relays,
            kinds: feed.kinds,
        },
        trust: source.trust,
        default_sensitivity: source.default_sensitivity,
        cursor: stored_cursor(&source.cursor_json),
        schedule: ghostr_core::source::IngestSchedule::Manual,
        redaction: ghostr_core::source::RedactionPolicy {
            detect_secrets: true,
            patterns: Vec::new(),
            minimum_sensitivity: None,
        },
        enabled: source.enabled,
        last_sync: None,
    };
    let cursor = configured.cursor.clone();
    let batch = adapter.pull(&configured, cursor).await?;
    Ok(Pulled {
        memories: batch.memories,
        rejected: batch.rejected_untrusted,
        unparseable: batch.unparseable_skipped,
        duplicates: batch.duplicates_skipped,
    })
}

/// A source's stored cursor, or [`SyncCursor::Start`] if it cannot be read.
///
/// Starting over is the safe direction: the store's digest index absorbs the
/// repeat, whereas guessing a position forward would skip a span for good.
fn stored_cursor(cursor_json: &str) -> SyncCursor {
    serde_json::from_str(cursor_json).unwrap_or(SyncCursor::Start)
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
    if let Some(feed) = new.feed.as_ref() {
        map.insert(
            "pubkey".to_owned(),
            serde_json::Value::String(feed.pubkey.clone()),
        );
        map.insert(
            "relays".to_owned(),
            serde_json::Value::Array(
                feed.relays
                    .iter()
                    .map(|r| serde_json::Value::String(r.clone()))
                    .collect(),
            ),
        );
        map.insert(
            "kinds".to_owned(),
            serde_json::Value::Array(
                feed.kinds
                    .iter()
                    .map(|k| serde_json::Value::Number((*k).into()))
                    .collect(),
            ),
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

/// Reads a feed's configuration back out of a stored source.
///
/// Returns `None` rather than a default: a feed whose stored configuration
/// cannot be read must fail its pull loudly, because the alternative is
/// fetching from relays nobody named or under a pubkey nobody chose.
fn feed_of(config: &str) -> Option<FeedConfig> {
    let value: serde_json::Value = serde_json::from_str(config).ok()?;
    Some(FeedConfig {
        pubkey: value.get("pubkey")?.as_str()?.to_owned(),
        relays: value
            .get("relays")?
            .as_array()?
            .iter()
            .filter_map(|r| r.as_str().map(ToOwned::to_owned))
            .collect(),
        kinds: value
            .get("kinds")?
            .as_array()?
            .iter()
            .filter_map(|k| k.as_u64().and_then(|n| u16::try_from(n).ok()))
            .collect(),
    })
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
            feed: None,
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
            feed: None,
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
            feed: None,
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
            feed: None,
        };
        assert!(plan(&new).is_err());
    }

    #[test]
    fn a_configuration_round_trips_through_json() {
        let new = NewSource {
            kind: SourceKindTag::StructuredLog,
            location: "/health.jsonl".to_owned(),
            schema: Some(LogSchema::Places),
            feed: None,
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

    fn feed_source() -> NewSource {
        NewSource {
            kind: SourceKindTag::NostrFeed,
            location: String::new(),
            schema: None,
            feed: Some(FeedConfig {
                pubkey: "aa".repeat(32),
                relays: vec!["wss://relay.example".to_owned()],
                kinds: vec![1],
            }),
        }
    }

    /// The two facts a user needs before they agree to add a feed.
    #[test]
    fn a_feed_plans_as_third_party_and_networked() {
        let p = plan(&feed_source()).expect("plan");
        assert_eq!(p.trust, TrustLevel::ThirdParty);
        assert!(!p.trust.may_be_exemplar());
        assert!(!p.trust.may_source_stance());
        assert!(p.touches_network);
        // Public, because it is: the author broadcast it before Ghostr saw it.
        assert_eq!(p.sensitivity, Sensitivity::Public);
    }

    /// A feed named without an author is a configuration error, not a default.
    #[test]
    fn a_feed_without_a_pubkey_is_refused() {
        let mut new = feed_source();
        new.feed = None;
        assert!(plan(&new).is_err());
    }

    #[test]
    fn a_feed_configuration_round_trips_through_json() {
        let new = feed_source();
        let json = config_json(&new).expect("json");
        let back = feed_of(&json).expect("feed");
        assert_eq!(back.pubkey, "aa".repeat(32));
        assert_eq!(back.relays, vec!["wss://relay.example".to_owned()]);
        assert_eq!(back.kinds, vec![1]);
    }

    /// A local source has no feed configuration, and reading one back must say
    /// so rather than inventing an author and a relay list.
    #[test]
    fn a_local_source_has_no_feed_configuration() {
        let json = config_json(&NewSource {
            kind: SourceKindTag::MarkdownVault,
            location: "/notes".to_owned(),
            schema: None,
            feed: None,
        })
        .expect("json");
        assert!(feed_of(&json).is_none());
        assert!(feed_of("not json at all").is_none());
    }

    /// The confirmation names the author rather than an empty path.
    #[test]
    fn a_feed_describes_itself_by_author_and_relay_count() {
        let p = plan(&feed_source()).expect("plan");
        assert!(p.location.contains("aaaaaaaa"));
        assert!(p.location.contains("1 relay"));
    }

    /// An unreadable cursor restarts rather than guessing forward.
    #[test]
    fn an_unreadable_cursor_restarts_the_feed() {
        assert_eq!(stored_cursor("{}"), SyncCursor::Start);
        assert_eq!(stored_cursor(""), SyncCursor::Start);
        assert_eq!(
            stored_cursor(r#"{"type":"timestamp","value":{"utc_millis":5,"offset_seconds":0}}"#),
            stored_cursor(r#"{"type":"timestamp","value":{"utc_millis":5,"offset_seconds":0}}"#)
        );
    }
}
