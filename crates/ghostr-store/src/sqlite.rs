//! The SQLite-backed store.
//!
//! One connection, opened against a file in the data directory. Every content
//! column is sealed with the DEK before it reaches SQLite, so the database file
//! is ciphertext plus queryable metadata (see [`schema`](crate::schema)).

use std::path::{Path, PathBuf};

use chrono::NaiveDate;
use chrono_tz::Tz;
use ghostr_core::footage::{ChainTip, Commitment, Footage};
use ghostr_core::hash::Hash32;
use ghostr_core::identity::PublicKey;
use ghostr_core::ids::{ChainId, MemoryId, SourceId};
use ghostr_core::memory::{Memory, MemoryBody, MemoryKind, Provenance};
use ghostr_core::sensitivity::{Sensitivity, TrustLevel};
use ghostr_core::time::Timestamp;
use ghostr_crypto::kdf::{Dek, open_row, seal_row};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};

use crate::memory::{MemoryQuery, RedactionReason, TimeRange};
use crate::schema::{SCHEMA_V1, SCHEMA_V2, SCHEMA_V3, SCHEMA_V4, SCHEMA_V5, SCHEMA_V6, meta_key};

/// The database filename inside the data directory.
pub const DB_FILENAME: &str = "ghostr.db";

/// The schema version this build writes.
pub const SCHEMA_VERSION: u32 = 6;

/// A SQLite-backed Ghostr store.
pub struct SqliteStore {
    conn: Connection,
    path: PathBuf,
}

impl core::fmt::Debug for SqliteStore {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SqliteStore")
            .field("path", &self.path)
            .finish()
    }
}

/// Encodes a row payload for storage.
///
/// Plain CBOR, not the canonical encoding from `ghostr-core`. The distinction is
/// deliberate and worth being precise about: canonical CBOR exists so that one
/// value has exactly one byte representation, which matters only for things that
/// get *hashed*. A row payload is encrypted storage — the commitment for a day
/// is computed separately over its Merkle leaves — so it needs no such
/// guarantee, and requiring one would ban the `f32` fields that mood readings
/// and salience legitimately use.
fn encode_row<T: Serialize>(value: &T) -> crate::Result<Vec<u8>> {
    let mut out = Vec::new();
    ciborium::into_writer(value, &mut out).map_err(|_| crate::Error::Backend {
        operation: "encode row payload",
    })?;
    Ok(out)
}

/// Decodes a row payload written by [`encode_row`].
fn decode_row<T: serde::de::DeserializeOwned>(
    bytes: &[u8],
    table: &'static str,
) -> crate::Result<T> {
    ciborium::from_reader(bytes).map_err(|_| crate::Error::RowDecryptFailed { table })
}

/// The parts of a [`Memory`] that are sealed rather than indexed.
///
/// Split out as its own serialisable type so that exactly one place decides what
/// is encrypted and what is queryable. Adding a field here encrypts it; adding a
/// column encrypts nothing.
#[derive(Debug, Serialize, Deserialize)]
struct SealedMemoryBody {
    text: String,
    structured: Option<Vec<u8>>,
    external_id: Option<String>,
    url: Option<String>,
    entities: Vec<String>,
}

/// The sealed half of a [`Footage`].
#[derive(Debug, Serialize, Deserialize)]
struct SealedFootageBody {
    highlights: Vec<ghostr_core::footage::Highlight>,
    people: Vec<ghostr_core::footage::PersonBeat>,
    mood: ghostr_core::footage::MoodReading,
    open_threads: Vec<ghostr_core::footage::Thread>,
    closed_loops: Vec<ghostr_core::ids::ThreadId>,
    unresolved: Vec<ghostr_core::footage::OpenQuestion>,
    memory_ids: Vec<MemoryId>,
    amendments: Vec<ghostr_core::footage::Amendment>,
    persona_version: ghostr_core::ids::PersonaVersion,
}

impl SqliteStore {
    /// Opens or creates the store at `dir`, applying migrations.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Backend`](crate::Error::Backend) if the database cannot
    /// be opened, or [`Error::SchemaTooNew`](crate::Error::SchemaTooNew) if it
    /// was written by a later build.
    pub fn open(dir: &Path) -> crate::Result<Self> {
        std::fs::create_dir_all(dir).map_err(|_| crate::Error::Backend {
            operation: "create data directory",
        })?;
        let path = dir.join(DB_FILENAME);
        let conn = Connection::open(&path).map_err(|_| crate::Error::Backend {
            operation: "open database",
        })?;

        // Foreign keys are off by default in SQLite, which would silently allow a
        // footage to reference a memory that does not exist.
        conn.execute_batch(
            "PRAGMA foreign_keys = ON;
             PRAGMA journal_mode = WAL;
             PRAGMA synchronous = FULL;",
        )
        .map_err(|_| crate::Error::Backend {
            operation: "set pragmas",
        })?;

        let store = Self { conn, path };
        store.migrate()?;
        Ok(store)
    }

    /// The database file path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    fn migrate(&self) -> crate::Result<()> {
        let existing: Option<String> = self
            .conn
            .query_row(
                "SELECT value FROM meta WHERE key = ?1",
                [meta_key::SCHEMA_VERSION],
                |r| r.get(0),
            )
            .optional()
            .unwrap_or(None);

        // 0 means "no schema at all yet". Every pending migration is applied in
        // order from whatever version is on disk, so a v1 vault created by M0
        // upgrades rather than failing to open.
        let current = match existing.as_deref().map(str::parse::<u32>) {
            Some(Ok(v)) if v > SCHEMA_VERSION => {
                // Refuse rather than guess. A downgrade that writes with an older
                // understanding of the schema can corrupt a chain beyond repair.
                return Err(crate::Error::SchemaTooNew {
                    found: v,
                    supported: SCHEMA_VERSION,
                });
            }
            Some(Ok(v)) => v,
            _ => 0,
        };

        // (applies_when_current_is_at_most, sql)
        for (from, sql) in [
            (0u32, SCHEMA_V1),
            (1, SCHEMA_V2),
            (2, SCHEMA_V3),
            (3, SCHEMA_V4),
            (4, SCHEMA_V5),
            (5, SCHEMA_V6),
        ] {
            if current <= from {
                self.conn
                    .execute_batch(sql)
                    .map_err(|_| crate::Error::Backend {
                        operation: "apply migration",
                    })?;
            }
        }
        if current != SCHEMA_VERSION {
            self.set_meta(meta_key::SCHEMA_VERSION, &SCHEMA_VERSION.to_string())?;
        }
        Ok(())
    }

    /// Writes a `meta` key.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Backend`](crate::Error::Backend) if the write fails.
    pub fn set_meta(&self, key: &str, value: &str) -> crate::Result<()> {
        self.conn
            .execute(
                "INSERT INTO meta (key, value) VALUES (?1, ?2)
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                params![key, value],
            )
            .map_err(|_| crate::Error::Backend {
                operation: "write meta",
            })?;
        Ok(())
    }

    /// Reads a `meta` key.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Backend`](crate::Error::Backend) if the read fails.
    pub fn meta(&self, key: &str) -> crate::Result<Option<String>> {
        self.conn
            .query_row("SELECT value FROM meta WHERE key = ?1", [key], |r| r.get(0))
            .optional()
            .map_err(|_| crate::Error::Backend {
                operation: "read meta",
            })
    }

    /// Records the identity and genesis link for a fresh store.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Backend`](crate::Error::Backend) if the write fails.
    pub fn init_chain(
        &self,
        chain_id: ChainId,
        identity: &PublicKey,
        genesis_link: Hash32,
        home_tz: Tz,
        created_at: Timestamp,
    ) -> crate::Result<()> {
        self.set_meta(meta_key::CHAIN_ID, &chain_id.as_uuid().to_string())?;
        self.set_meta(meta_key::IDENTITY_PUBKEY, &identity.to_hex())?;
        self.set_meta(meta_key::GENESIS_LINK, &genesis_link.to_hex())?;
        self.set_meta(meta_key::HOME_TZ, home_tz.name())?;
        self.set_meta(meta_key::CREATED_AT, &created_at.utc_millis().to_string())?;
        Ok(())
    }

    /// The genesis link recorded at init.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Backend`](crate::Error::Backend) if it is missing or
    /// malformed.
    pub fn genesis_link(&self) -> crate::Result<Hash32> {
        let hex = self
            .meta(meta_key::GENESIS_LINK)?
            .ok_or(crate::Error::Backend {
                operation: "store has no genesis link",
            })?;
        Hash32::from_hex(&hex).map_err(|_| crate::Error::Backend {
            operation: "parse genesis link",
        })
    }

    /// The home timezone recorded at init.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Backend`](crate::Error::Backend) if it is missing or
    /// unparseable.
    pub fn home_tz(&self) -> crate::Result<Tz> {
        self.meta(meta_key::HOME_TZ)?
            .and_then(|s| s.parse().ok())
            .ok_or(crate::Error::Backend {
                operation: "store has no home timezone",
            })
    }

    /// Registers a source, or returns the existing one with the same kind tag.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Backend`](crate::Error::Backend) if the write fails.
    pub fn upsert_source(
        &self,
        dek: &Dek,
        id: SourceId,
        kind_tag: &str,
        config: &str,
        nonce: [u8; 24],
    ) -> crate::Result<SourceId> {
        self.upsert_source_with(
            dek,
            &NewSourceRow {
                id,
                kind_tag,
                config,
                trust: TrustLevel::FirstParty,
                sensitivity: Sensitivity::Private,
            },
            nonce,
        )
    }

    /// Inserts a source, or returns the id of the one already configured the
    /// same way.
    ///
    /// Identity is `(kind, config)`, not `kind`: two markdown vaults at
    /// different paths are two sources, and re-running `source add` on the same
    /// path is not. The configuration stays sealed, so the match is on a keyed
    /// digest of it — deterministic with the DEK, unforgeable without.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Backend`](crate::Error::Backend) if the write fails.
    pub fn upsert_source_with(
        &self,
        dek: &Dek,
        new: &NewSourceRow<'_>,
        nonce: [u8; 24],
    ) -> crate::Result<SourceId> {
        let NewSourceRow {
            id,
            kind_tag,
            config,
            trust,
            sensitivity,
        } = *new;
        let tag = self.config_tag(dek, kind_tag, config)?;
        if let Some(existing) = self
            .conn
            .query_row(
                "SELECT id FROM source WHERE kind = ?1 AND config_tag = ?2",
                params![kind_tag, tag],
                |r| r.get::<_, String>(0),
            )
            .optional()
            .map_err(|_| crate::Error::Backend {
                operation: "look up source",
            })?
        {
            return SourceId::parse(&existing).map_err(|_| crate::Error::Backend {
                operation: "parse stored source id",
            });
        }
        let aad = format!("source:{id}");
        let sealed = seal_row(dek, config.as_bytes(), &nonce, aad.as_bytes())?;
        self.conn
            .execute(
                "INSERT INTO source
                 (id, kind, trust, default_sensitivity, enabled, cursor_json,
                  config_nonce, config_sealed, config_tag)
                 VALUES (?1, ?2, ?3, ?4, 1, '{}', ?5, ?6, ?7)",
                params![
                    id.to_string(),
                    kind_tag,
                    trust_str(trust),
                    sensitivity_str(sensitivity),
                    nonce.to_vec(),
                    sealed,
                    tag
                ],
            )
            .map_err(|_| crate::Error::Backend {
                operation: "insert source",
            })?;
        Ok(id)
    }

    /// A keyed, deterministic digest of a source's configuration.
    ///
    /// Same construction as entity name tags: the DEK is not exposed as bytes,
    /// so the tag is a hash of the configuration sealed under a fixed nonce.
    fn config_tag(&self, dek: &Dek, kind_tag: &str, config: &str) -> crate::Result<String> {
        let material = format!("{kind_tag}\u{0}{}", config.trim());
        let sealed = seal_row(dek, material.as_bytes(), &[0u8; 24], b"source-config-tag")?;
        Ok(ghostr_core::hash::tagged_hash(ghostr_core::hash::Tag::MetaLeaf, &sealed).to_hex())
    }

    /// Every configured source, ordered by id.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Backend`](crate::Error::Backend) if the read fails.
    pub fn all_sources(&self, dek: &Dek) -> crate::Result<Vec<StoredSource>> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT id, kind, trust, default_sensitivity, enabled, cursor_json,
                        config_nonce, config_sealed
                 FROM source ORDER BY id",
            )
            .map_err(|_| crate::Error::Backend {
                operation: "prepare source list",
            })?;
        let rows = stmt
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, i64>(4)?,
                    r.get::<_, String>(5)?,
                    r.get::<_, Vec<u8>>(6)?,
                    r.get::<_, Vec<u8>>(7)?,
                ))
            })
            .map_err(|_| crate::Error::Backend {
                operation: "list sources",
            })?;

        let mut out = Vec::new();
        for row in rows {
            let (id, kind, trust, sensitivity, enabled, cursor, nonce, sealed) =
                row.map_err(|_| crate::Error::Backend {
                    operation: "read source row",
                })?;
            let nonce: [u8; 24] = nonce.try_into().map_err(|_| crate::Error::Backend {
                operation: "source nonce length",
            })?;
            let aad = format!("source:{id}");
            let config = open_row(dek, &sealed, &nonce, aad.as_bytes())
                .map_err(|_| crate::Error::RowDecryptFailed { table: "source" })?;
            out.push(StoredSource {
                id: SourceId::parse(&id).map_err(|_| crate::Error::Backend {
                    operation: "parse source id",
                })?,
                kind_tag: kind,
                trust: trust_from_str(&trust),
                default_sensitivity: sensitivity_from_str(&sensitivity),
                enabled: enabled != 0,
                cursor_json: cursor,
                config: String::from_utf8(config)
                    .map_err(|_| crate::Error::RowDecryptFailed { table: "source" })?,
            });
        }
        Ok(out)
    }

    /// Records a source's resumable position.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Backend`](crate::Error::Backend) if the write fails.
    pub fn set_source_cursor(&self, id: SourceId, cursor_json: &str) -> crate::Result<()> {
        self.conn
            .execute(
                "UPDATE source SET cursor_json = ?2 WHERE id = ?1",
                params![id.to_string(), cursor_json],
            )
            .map_err(|_| crate::Error::Backend {
                operation: "set source cursor",
            })?;
        Ok(())
    }

    /// Whether a raw-content digest has already been ingested from this source.
    ///
    /// Ingest is idempotent: re-running over a vault must not duplicate notes.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Backend`](crate::Error::Backend) if the read fails.
    pub fn has_raw_hash(&self, source: SourceId, raw_hash: Hash32) -> crate::Result<bool> {
        self.conn
            .query_row(
                "SELECT 1 FROM memory WHERE source_id = ?1 AND raw_hash = ?2",
                params![source.to_string(), raw_hash.to_hex()],
                |_| Ok(()),
            )
            .optional()
            .map(|o| o.is_some())
            .map_err(|_| crate::Error::Backend {
                operation: "check raw hash",
            })
    }

    /// Inserts a memory, sealing its content.
    ///
    /// # Errors
    ///
    /// Returns [`Error::AppendOnlyViolation`](crate::Error::AppendOnlyViolation)
    /// if the id exists.
    pub fn put_memory(&self, dek: &Dek, memory: &Memory, nonce: [u8; 24]) -> crate::Result<()> {
        let body = SealedMemoryBody {
            text: memory.body.text.clone(),
            structured: memory
                .body
                .structured
                .as_ref()
                .map(|s| s.as_bytes().to_vec()),
            external_id: memory.provenance.external_id.clone(),
            url: memory.provenance.url.clone(),
            entities: memory.entities.iter().map(|e| e.id.to_string()).collect(),
        };
        let plaintext = encode_row(&body)?;
        let aad = format!("memory:{}", memory.id);
        let sealed = seal_row(dek, &plaintext, &nonce, aad.as_bytes())?;

        self.conn
            .execute(
                "INSERT INTO memory
                 (id, source_id, occurred_at, occurred_off, ingested_at, ingested_off,
                  kind, sensitivity, salience, supersedes, raw_hash, salt,
                  body_nonce, body_sealed)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
                params![
                    memory.id.to_string(),
                    memory.source_id.to_string(),
                    memory.occurred_at.map(|t| t.utc_millis()),
                    memory.occurred_at.map(|t| i64::from(t.offset_seconds())),
                    memory.ingested_at.utc_millis(),
                    i64::from(memory.ingested_at.offset_seconds()),
                    kind_str(memory.kind),
                    sensitivity_str(memory.sensitivity),
                    i64::from(
                        ghostr_core::canonical::ratio_to_fixed(memory.salience, "salience")
                            .map_err(|_| crate::Error::Backend {
                                operation: "salience range"
                            })?
                    ),
                    memory.supersedes.map(|s| s.to_string()),
                    memory.provenance.raw_hash.to_hex(),
                    memory.salt.to_vec(),
                    nonce.to_vec(),
                    sealed,
                ],
            )
            .map_err(|e| match e {
                rusqlite::Error::SqliteFailure(f, _)
                    if f.code == rusqlite::ErrorCode::ConstraintViolation =>
                {
                    crate::Error::AppendOnlyViolation { table: "memory" }
                }
                _ => crate::Error::Backend {
                    operation: "insert memory",
                },
            })?;
        Ok(())
    }

    /// Reads one memory.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Shredded`](crate::Error::Shredded) if the content was
    /// crypto-shredded, which is distinct from the memory not existing.
    pub fn get_memory(&self, dek: &Dek, id: MemoryId) -> crate::Result<Option<Memory>> {
        let row = self
            .conn
            .query_row(
                "SELECT id, source_id, occurred_at, occurred_off, ingested_at, ingested_off,
                        kind, sensitivity, salience, supersedes, raw_hash, salt,
                        body_nonce, body_sealed, shredded_at
                 FROM memory WHERE id = ?1",
                [id.to_string()],
                |r| Ok(RawMemory::from_row(r)),
            )
            .optional()
            .map_err(|_| crate::Error::Backend {
                operation: "read memory",
            })?;

        let Some(raw) = row.transpose().map_err(|_| crate::Error::Backend {
            operation: "decode memory row",
        })?
        else {
            return Ok(None);
        };
        if raw.shredded {
            return Err(crate::Error::Shredded { id });
        }
        Ok(Some(raw.decrypt(dek)?))
    }

    /// Every memory whose effective time falls in `range`, ordered by id.
    ///
    /// "Effective time" is `occurred_at` when known and `ingested_at` otherwise,
    /// which is what decides the day a note belongs to (SPEC §6).
    ///
    /// # Errors
    ///
    /// Returns [`Error::Backend`](crate::Error::Backend) if the read fails.
    pub fn window(&self, dek: &Dek, range: TimeRange) -> crate::Result<Vec<Memory>> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT id, source_id, occurred_at, occurred_off, ingested_at, ingested_off,
                        kind, sensitivity, salience, supersedes, raw_hash, salt,
                        body_nonce, body_sealed, shredded_at
                 FROM memory
                 WHERE COALESCE(occurred_at, ingested_at) >= ?1
                   AND COALESCE(occurred_at, ingested_at) <  ?2
                   AND shredded_at IS NULL
                 ORDER BY id",
            )
            .map_err(|_| crate::Error::Backend {
                operation: "prepare window query",
            })?;
        let rows = stmt
            .query_map(
                params![range.start.utc_millis(), range.end.utc_millis()],
                |r| Ok(RawMemory::from_row(r)),
            )
            .map_err(|_| crate::Error::Backend {
                operation: "run window query",
            })?;

        let mut out = Vec::new();
        for row in rows {
            let raw = row
                .map_err(|_| crate::Error::Backend {
                    operation: "read window row",
                })?
                .map_err(|_| crate::Error::Backend {
                    operation: "decode window row",
                })?;
            out.push(raw.decrypt(dek)?);
        }
        Ok(out)
    }

    /// Memories that arrived after their day had already been sealed.
    ///
    /// A memory is *late* when its effective time falls before `sealed_through`
    /// — the end of the most recently sealed window — but it was ingested at or
    /// after `ingested_from`, which is the moment that seal happened. It missed
    /// the day it belongs to, and that day is immutable (I2).
    ///
    /// Ordered by effective time so the amendments a caller builds from these
    /// come out in a stable order; the footage carrying them is hashed.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Backend`](crate::Error::Backend) if the read fails.
    pub fn late_arrivals(
        &self,
        dek: &Dek,
        sealed_through: Timestamp,
        ingested_from: Timestamp,
    ) -> crate::Result<Vec<Memory>> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT id, source_id, occurred_at, occurred_off, ingested_at, ingested_off,
                        kind, sensitivity, salience, supersedes, raw_hash, salt,
                        body_nonce, body_sealed, shredded_at
                 FROM memory
                 WHERE COALESCE(occurred_at, ingested_at) < ?1
                   AND ingested_at >= ?2
                   AND shredded_at IS NULL
                 ORDER BY COALESCE(occurred_at, ingested_at), id",
            )
            .map_err(|_| crate::Error::Backend {
                operation: "prepare late-arrival query",
            })?;
        let rows = stmt
            .query_map(
                params![sealed_through.utc_millis(), ingested_from.utc_millis()],
                |r| Ok(RawMemory::from_row(r)),
            )
            .map_err(|_| crate::Error::Backend {
                operation: "run late-arrival query",
            })?;

        let mut out = Vec::new();
        for row in rows {
            let raw = row
                .map_err(|_| crate::Error::Backend {
                    operation: "read late-arrival row",
                })?
                .map_err(|_| crate::Error::Backend {
                    operation: "decode late-arrival row",
                })?;
            out.push(raw.decrypt(dek)?);
        }
        Ok(out)
    }

    /// The sealed sequence whose window contains `at`, if any.
    ///
    /// Backs amendment targeting: a late memory has to name the day it should
    /// have been in, and that day is found by its window, not by its date — the
    /// two differ whenever a cutoff is not midnight.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Backend`](crate::Error::Backend) if the read fails.
    pub fn sealed_seq_covering(&self, at: Timestamp) -> crate::Result<Option<u64>> {
        self.conn
            .query_row(
                "SELECT seq FROM footage
                 WHERE window_start <= ?1 AND window_end > ?1
                 ORDER BY seq
                 LIMIT 1",
                [at.utc_millis()],
                |r| r.get::<_, i64>(0),
            )
            .optional()
            .map(|o| o.map(|s| s.max(0).unsigned_abs()))
            .map_err(|_| crate::Error::Backend {
                operation: "find sealed window",
            })
    }

    /// Every memory, ordered by id. Backs `verify` and `ingest` reporting.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Backend`](crate::Error::Backend) if the read fails.
    pub fn all_memories(&self, dek: &Dek) -> crate::Result<Vec<Memory>> {
        self.window(
            dek,
            TimeRange {
                start: Timestamp::new(i64::MIN / 2, 0),
                end: Timestamp::new(i64::MAX / 2, 0),
            },
        )
    }

    /// How many memories are stored.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Backend`](crate::Error::Backend) if the read fails.
    pub fn memory_count(&self) -> crate::Result<u64> {
        self.conn
            .query_row("SELECT COUNT(*) FROM memory", [], |r| r.get::<_, i64>(0))
            .map(|n| n.max(0).unsigned_abs())
            .map_err(|_| crate::Error::Backend {
                operation: "count memories",
            })
    }

    /// Crypto-shreds a memory: destroys its content and its salt, keeps its leaf.
    ///
    /// Because the leaf is salted, dropping content *and salt* leaves a hash that
    /// still verifies the chain while the commitment becomes unopenable and the
    /// content unrecoverable. The chain still records that something was there
    /// and when; nothing records what (SPEC Q6).
    ///
    /// # Errors
    ///
    /// Returns [`Error::MemoryNotFound`](crate::Error::MemoryNotFound) if the id
    /// is unknown.
    pub fn shred(&self, id: MemoryId, reason: RedactionReason, at: Timestamp) -> crate::Result<()> {
        let changed = self
            .conn
            .execute(
                "UPDATE memory
                 SET salt = NULL, body_nonce = NULL, body_sealed = NULL,
                     shredded_at = ?2, shred_reason = ?3
                 WHERE id = ?1",
                params![id.to_string(), at.utc_millis(), format!("{reason:?}")],
            )
            .map_err(|_| crate::Error::Backend {
                operation: "shred memory",
            })?;
        if changed == 0 {
            return Err(crate::Error::MemoryNotFound { id });
        }
        Ok(())
    }

    /// Seals a footage. Fails rather than overwrites.
    ///
    /// # Errors
    ///
    /// Returns [`Error::DuplicateSeq`](crate::Error::DuplicateSeq) if the `seq`
    /// exists — the fork guard — or [`Error::ChainGap`](crate::Error::ChainGap)
    /// if it does not directly follow the tip.
    pub fn seal_footage(
        &self,
        dek: &Dek,
        footage: &Footage,
        leaves: &[(MemoryId, Hash32)],
        nonce: [u8; 24],
    ) -> crate::Result<()> {
        let expected = self.tip()?.map_or(1, |t| t.seq + 1);
        if footage.seq != expected {
            if self.footage_exists(footage.seq)? {
                return Err(crate::Error::DuplicateSeq { seq: footage.seq });
            }
            return Err(crate::Error::ChainGap {
                expected,
                got: footage.seq,
            });
        }

        let body = SealedFootageBody {
            highlights: footage.highlights.clone(),
            people: footage.people.clone(),
            mood: footage.mood.clone(),
            open_threads: footage.open_threads.clone(),
            closed_loops: footage.closed_loops.clone(),
            unresolved: footage.unresolved.clone(),
            memory_ids: footage.memory_ids.clone(),
            amendments: footage.amendments.clone(),
            persona_version: footage.persona_version,
        };
        let plaintext = encode_row(&body)?;
        let aad = format!("footage:{}", footage.seq);
        let sealed = seal_row(dek, &plaintext, &nonce, aad.as_bytes())?;

        // One transaction: there is no valid state between "not sealed" and
        // "sealed", and a half-written link is indistinguishable from a tampered
        // one (SPEC I2, I3).
        // `unchecked_transaction` so this takes `&self`: the caller already holds
        // a shared borrow of the engine in order to reach the DEK, and there is
        // exactly one connection with no nested transactions, so the check it
        // skips cannot fire here.
        let tx = self
            .conn
            .unchecked_transaction()
            .map_err(|_| crate::Error::Backend {
                operation: "begin seal transaction",
            })?;
        tx.execute(
            "INSERT INTO footage
             (seq, date, tz, window_start, window_end, empty, merkle_root, prev_link,
              link, leaf_count, sealed_at, sealed_off, body_nonce, body_sealed)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
            params![
                i64::try_from(footage.seq).unwrap_or(i64::MAX),
                footage.date.to_string(),
                footage.tz.name(),
                footage.window.0.utc_millis(),
                footage.window.1.utc_millis(),
                i64::from(footage.empty),
                footage.commitment.merkle_root.to_hex(),
                footage.commitment.prev_link.to_hex(),
                footage.commitment.link.to_hex(),
                i64::from(footage.commitment.leaf_count),
                footage.sealed_at.utc_millis(),
                i64::from(footage.sealed_at.offset_seconds()),
                nonce.to_vec(),
                sealed,
            ],
        )
        .map_err(|e| match e {
            rusqlite::Error::SqliteFailure(f, _)
                if f.code == rusqlite::ErrorCode::ConstraintViolation =>
            {
                crate::Error::DuplicateSeq { seq: footage.seq }
            }
            _ => crate::Error::Backend {
                operation: "insert footage",
            },
        })?;

        for (memory_id, leaf) in leaves {
            tx.execute(
                "INSERT INTO footage_memory (seq, memory_id, leaf) VALUES (?1, ?2, ?3)",
                params![
                    i64::try_from(footage.seq).unwrap_or(i64::MAX),
                    memory_id.to_string(),
                    leaf.to_hex()
                ],
            )
            .map_err(|_| crate::Error::Backend {
                operation: "insert footage memory",
            })?;
        }

        tx.commit().map_err(|_| crate::Error::Backend {
            operation: "commit seal",
        })?;
        Ok(())
    }

    fn footage_exists(&self, seq: u64) -> crate::Result<bool> {
        self.conn
            .query_row(
                "SELECT 1 FROM footage WHERE seq = ?1",
                [i64::try_from(seq).unwrap_or(i64::MAX)],
                |_| Ok(()),
            )
            .optional()
            .map(|o| o.is_some())
            .map_err(|_| crate::Error::Backend {
                operation: "check footage",
            })
    }

    /// Reads one sealed footage.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Backend`](crate::Error::Backend) if the read fails.
    pub fn get_footage(&self, dek: &Dek, seq: u64) -> crate::Result<Option<Footage>> {
        let row = self
            .conn
            .query_row(
                "SELECT seq, date, tz, window_start, window_end, empty, merkle_root,
                        prev_link, link, leaf_count, sealed_at, sealed_off,
                        body_nonce, body_sealed
                 FROM footage WHERE seq = ?1",
                [i64::try_from(seq).unwrap_or(i64::MAX)],
                |r| Ok(RawFootage::from_row(r)),
            )
            .optional()
            .map_err(|_| crate::Error::Backend {
                operation: "read footage",
            })?;
        let Some(raw) = row.transpose().map_err(|_| crate::Error::Backend {
            operation: "decode footage row",
        })?
        else {
            return Ok(None);
        };
        Ok(Some(raw.decrypt(dek)?))
    }

    /// Every sealed footage, oldest first.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Backend`](crate::Error::Backend) if the read fails.
    pub fn all_footage(&self, dek: &Dek) -> crate::Result<Vec<Footage>> {
        let seqs: Vec<i64> = {
            let mut stmt = self
                .conn
                .prepare("SELECT seq FROM footage ORDER BY seq")
                .map_err(|_| crate::Error::Backend {
                    operation: "prepare footage list",
                })?;
            let rows = stmt
                .query_map([], |r| r.get(0))
                .map_err(|_| crate::Error::Backend {
                    operation: "list footage",
                })?;
            rows.collect::<Result<_, _>>()
                .map_err(|_| crate::Error::Backend {
                    operation: "collect footage seqs",
                })?
        };
        seqs.into_iter()
            .map(|s| {
                self.get_footage(dek, s.unsigned_abs())?
                    .ok_or(crate::Error::Backend {
                        operation: "footage vanished mid-read",
                    })
            })
            .collect()
    }

    /// The leaves committed by one footage, in stored order.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Backend`](crate::Error::Backend) if the read fails.
    pub fn footage_leaves(&self, seq: u64) -> crate::Result<Vec<(MemoryId, Hash32)>> {
        let mut stmt = self
            .conn
            .prepare("SELECT memory_id, leaf FROM footage_memory WHERE seq = ?1 ORDER BY memory_id")
            .map_err(|_| crate::Error::Backend {
                operation: "prepare leaf query",
            })?;
        let rows = stmt
            .query_map([i64::try_from(seq).unwrap_or(i64::MAX)], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
            })
            .map_err(|_| crate::Error::Backend {
                operation: "read leaves",
            })?;
        let mut out = Vec::new();
        for row in rows {
            let (id, leaf) = row.map_err(|_| crate::Error::Backend {
                operation: "leaf row",
            })?;
            out.push((
                MemoryId::parse(&id).map_err(|_| crate::Error::Backend {
                    operation: "parse leaf memory id",
                })?,
                Hash32::from_hex(&leaf).map_err(|_| crate::Error::Backend {
                    operation: "parse leaf digest",
                })?,
            ));
        }
        Ok(out)
    }

    /// The head of the chain, or `None` before the first seal.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Backend`](crate::Error::Backend) if the read fails.
    pub fn tip(&self) -> crate::Result<Option<ChainTip>> {
        self.conn
            .query_row(
                "SELECT seq, link, sealed_at, sealed_off FROM footage
                 ORDER BY seq DESC LIMIT 1",
                [],
                |r| {
                    Ok((
                        r.get::<_, i64>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, i64>(2)?,
                        r.get::<_, i64>(3)?,
                    ))
                },
            )
            .optional()
            .map_err(|_| crate::Error::Backend {
                operation: "read tip",
            })?
            .map(|(seq, link, at, off)| {
                Ok(ChainTip {
                    seq: seq.unsigned_abs(),
                    link: Hash32::from_hex(&link).map_err(|_| crate::Error::Backend {
                        operation: "parse tip link",
                    })?,
                    sealed_at: Timestamp::new(at, i32::try_from(off).unwrap_or(0)),
                })
            })
            .transpose()
    }

    /// The most recent sealed date, used to find the next window.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Backend`](crate::Error::Backend) if the read fails.
    pub fn last_sealed_date(&self) -> crate::Result<Option<NaiveDate>> {
        self.conn
            .query_row(
                "SELECT date FROM footage ORDER BY seq DESC LIMIT 1",
                [],
                |r| r.get::<_, String>(0),
            )
            .optional()
            .map_err(|_| crate::Error::Backend {
                operation: "read last sealed date",
            })?
            .map(|s| {
                s.parse::<NaiveDate>().map_err(|_| crate::Error::Backend {
                    operation: "parse sealed date",
                })
            })
            .transpose()
    }

    /// Whether a date has already been sealed.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Backend`](crate::Error::Backend) if the read fails.
    pub fn date_is_sealed(&self, date: NaiveDate) -> crate::Result<Option<u64>> {
        self.conn
            .query_row(
                "SELECT seq FROM footage WHERE date = ?1",
                [date.to_string()],
                |r| r.get::<_, i64>(0),
            )
            .optional()
            .map(|o| o.map(i64::unsigned_abs))
            .map_err(|_| crate::Error::Backend {
                operation: "check sealed date",
            })
    }

    /// Records an anchor state for a sequence.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Backend`](crate::Error::Backend) if the write fails.
    pub fn put_anchor(&self, record: &AnchorRecord) -> crate::Result<()> {
        self.conn
            .execute(
                "INSERT INTO anchor (seq, state, digest, submitted_at, block_height, attempts, detail, ots)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                 ON CONFLICT(seq) DO UPDATE SET
                   state = excluded.state, submitted_at = excluded.submitted_at,
                   block_height = excluded.block_height, attempts = excluded.attempts,
                   detail = excluded.detail, ots = excluded.ots",
                params![
                    i64::try_from(record.seq).unwrap_or(i64::MAX),
                    record.state.as_str(),
                    record.digest.to_hex(),
                    record.submitted_at.map(|t| t.utc_millis()),
                    record.block_height.map(i64::from),
                    i64::from(record.attempts),
                    record.detail.clone(),
                    record.ots.clone(),
                ],
            )
            .map_err(|_| crate::Error::Backend { operation: "write anchor" })?;
        Ok(())
    }

    /// Reads an anchor record.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Backend`](crate::Error::Backend) if the read fails.
    pub fn get_anchor(&self, seq: u64) -> crate::Result<Option<AnchorRecord>> {
        self.conn
            .query_row(
                "SELECT seq, state, digest, submitted_at, block_height, attempts, detail, ots
                 FROM anchor WHERE seq = ?1",
                [i64::try_from(seq).unwrap_or(i64::MAX)],
                |r| {
                    Ok(AnchorRecord {
                        seq: r.get::<_, i64>(0)?.unsigned_abs(),
                        state: AnchorRecordState::from_str(&r.get::<_, String>(1)?),
                        digest: Hash32::from_hex(&r.get::<_, String>(2)?).unwrap_or(Hash32::zero()),
                        submitted_at: r.get::<_, Option<i64>>(3)?.map(|m| Timestamp::new(m, 0)),
                        block_height: r
                            .get::<_, Option<i64>>(4)?
                            .and_then(|h| u32::try_from(h).ok()),
                        attempts: u32::try_from(r.get::<_, i64>(5)?).unwrap_or(0),
                        detail: r.get(6)?,
                        ots: r.get(7)?,
                    })
                },
            )
            .optional()
            .map_err(|_| crate::Error::Backend {
                operation: "read anchor",
            })
    }
}

/// A persisted anchor state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnchorRecord {
    /// Which sequence this anchors.
    pub seq: u64,
    /// Where it stands.
    pub state: AnchorRecordState,
    /// The digest submitted.
    pub digest: Hash32,
    /// When it was submitted.
    pub submitted_at: Option<Timestamp>,
    /// Attested block height, once confirmed.
    pub block_height: Option<u32>,
    /// How many submission attempts were made.
    pub attempts: u32,
    /// Human-readable detail, e.g. the last transport error.
    pub detail: Option<String>,
    /// The serialised `.ots` proof.
    pub ots: Option<Vec<u8>>,
}

/// The state column of an [`AnchorRecord`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AnchorRecordState {
    /// Not yet submitted.
    Unanchored,
    /// Submitted, awaiting a calendar's Bitcoin transaction.
    Pending,
    /// Confirmed in a block.
    Confirmed,
    /// Submission failed.
    Failed,
}

impl AnchorRecordState {
    /// The stored string form.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unanchored => "unanchored",
            Self::Pending => "pending",
            Self::Confirmed => "confirmed",
            Self::Failed => "failed",
        }
    }

    fn from_str(s: &str) -> Self {
        match s {
            "pending" => Self::Pending,
            "confirmed" => Self::Confirmed,
            "failed" => Self::Failed,
            _ => Self::Unanchored,
        }
    }
}

/// A memory row before decryption.
struct RawMemory {
    id: String,
    source_id: String,
    occurred_at: Option<i64>,
    occurred_off: Option<i64>,
    ingested_at: i64,
    ingested_off: i64,
    kind: String,
    sensitivity: String,
    salience: i64,
    supersedes: Option<String>,
    raw_hash: String,
    salt: Option<Vec<u8>>,
    nonce: Option<Vec<u8>>,
    sealed: Option<Vec<u8>>,
    shredded: bool,
}

impl RawMemory {
    fn from_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            id: r.get(0)?,
            source_id: r.get(1)?,
            occurred_at: r.get(2)?,
            occurred_off: r.get(3)?,
            ingested_at: r.get(4)?,
            ingested_off: r.get(5)?,
            kind: r.get(6)?,
            sensitivity: r.get(7)?,
            salience: r.get(8)?,
            supersedes: r.get(9)?,
            raw_hash: r.get(10)?,
            salt: r.get(11)?,
            nonce: r.get(12)?,
            sealed: r.get(13)?,
            shredded: r.get::<_, Option<i64>>(14)?.is_some(),
        })
    }

    fn decrypt(self, dek: &Dek) -> crate::Result<Memory> {
        let id = MemoryId::parse(&self.id).map_err(|_| crate::Error::Backend {
            operation: "parse memory id",
        })?;
        let (Some(nonce), Some(sealed), Some(salt)) = (self.nonce, self.sealed, self.salt) else {
            return Err(crate::Error::Shredded { id });
        };
        let nonce: [u8; 24] = nonce.try_into().map_err(|_| crate::Error::Backend {
            operation: "memory nonce length",
        })?;
        let aad = format!("memory:{id}");
        let plaintext = open_row(dek, &sealed, &nonce, aad.as_bytes())
            .map_err(|_| crate::Error::RowDecryptFailed { table: "memory" })?;
        let body: SealedMemoryBody = decode_row(&plaintext, "memory")?;

        let salt: [u8; 32] = salt.try_into().map_err(|_| crate::Error::Backend {
            operation: "memory salt length",
        })?;

        Ok(Memory {
            id,
            source_id: SourceId::parse(&self.source_id).map_err(|_| crate::Error::Backend {
                operation: "parse source id",
            })?,
            occurred_at: self.occurred_at.map(|m| {
                Timestamp::new(
                    m,
                    i32::try_from(self.occurred_off.unwrap_or(0)).unwrap_or(0),
                )
            }),
            ingested_at: Timestamp::new(
                self.ingested_at,
                i32::try_from(self.ingested_off).unwrap_or(0),
            ),
            kind: kind_from_str(&self.kind),
            body: MemoryBody {
                text: body.text,
                structured: None,
                redactions: Vec::new(),
            },
            entities: Vec::new(),
            salience: ghostr_core::canonical::fixed_to_ratio(
                u32::try_from(self.salience).unwrap_or(0),
            ),
            sensitivity: sensitivity_from_str(&self.sensitivity),
            provenance: Provenance {
                source_id: SourceId::parse(&self.source_id).map_err(|_| crate::Error::Backend {
                    operation: "parse source id",
                })?,
                external_id: body.external_id,
                url: body.url,
                raw_hash: Hash32::from_hex(&self.raw_hash).map_err(|_| crate::Error::Backend {
                    operation: "parse raw hash",
                })?,
            },
            salt,
            supersedes: self
                .supersedes
                .as_deref()
                .map(MemoryId::parse)
                .transpose()
                .map_err(|_| crate::Error::Backend {
                    operation: "parse supersedes",
                })?,
            embedding: None,
        })
    }
}

/// A footage row before decryption.
struct RawFootage {
    seq: i64,
    date: String,
    tz: String,
    window_start: i64,
    window_end: i64,
    empty: i64,
    merkle_root: String,
    prev_link: String,
    link: String,
    leaf_count: i64,
    sealed_at: i64,
    sealed_off: i64,
    nonce: Vec<u8>,
    sealed: Vec<u8>,
}

impl RawFootage {
    fn from_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            seq: r.get(0)?,
            date: r.get(1)?,
            tz: r.get(2)?,
            window_start: r.get(3)?,
            window_end: r.get(4)?,
            empty: r.get(5)?,
            merkle_root: r.get(6)?,
            prev_link: r.get(7)?,
            link: r.get(8)?,
            leaf_count: r.get(9)?,
            sealed_at: r.get(10)?,
            sealed_off: r.get(11)?,
            nonce: r.get(12)?,
            sealed: r.get(13)?,
        })
    }

    fn decrypt(self, dek: &Dek) -> crate::Result<Footage> {
        let seq = self.seq.unsigned_abs();
        let nonce: [u8; 24] = self.nonce.try_into().map_err(|_| crate::Error::Backend {
            operation: "footage nonce length",
        })?;
        let aad = format!("footage:{seq}");
        let plaintext = open_row(dek, &self.sealed, &nonce, aad.as_bytes())
            .map_err(|_| crate::Error::RowDecryptFailed { table: "footage" })?;
        let body: SealedFootageBody = decode_row(&plaintext, "footage")?;

        Ok(Footage {
            seq,
            date: self.date.parse().map_err(|_| crate::Error::Backend {
                operation: "parse footage date",
            })?,
            tz: self.tz.parse().map_err(|_| crate::Error::Backend {
                operation: "parse footage tz",
            })?,
            window: (
                Timestamp::new(self.window_start, 0),
                Timestamp::new(self.window_end, 0),
            ),
            empty: self.empty != 0,
            highlights: body.highlights,
            people: body.people,
            mood: body.mood,
            open_threads: body.open_threads,
            closed_loops: body.closed_loops,
            unresolved: body.unresolved,
            memory_ids: body.memory_ids,
            amendments: body.amendments,
            persona_version: body.persona_version,
            commitment: Commitment {
                merkle_root: Hash32::from_hex(&self.merkle_root).map_err(|_| {
                    crate::Error::Backend {
                        operation: "parse merkle root",
                    }
                })?,
                prev_link: Hash32::from_hex(&self.prev_link).map_err(|_| {
                    crate::Error::Backend {
                        operation: "parse prev link",
                    }
                })?,
                link: Hash32::from_hex(&self.link).map_err(|_| crate::Error::Backend {
                    operation: "parse link",
                })?,
                leaf_count: u32::try_from(self.leaf_count).unwrap_or(0),
            },
            sealed_at: Timestamp::new(self.sealed_at, i32::try_from(self.sealed_off).unwrap_or(0)),
        })
    }
}

const fn kind_str(kind: MemoryKind) -> &'static str {
    match kind {
        MemoryKind::Utterance => "utterance",
        MemoryKind::Observation => "observation",
        MemoryKind::Event => "event",
        MemoryKind::Fact => "fact",
        MemoryKind::Relationship => "relationship",
        MemoryKind::Habit => "habit",
        MemoryKind::Location => "location",
        MemoryKind::Artifact => "artifact",
        _ => "utterance",
    }
}

fn kind_from_str(s: &str) -> MemoryKind {
    match s {
        "observation" => MemoryKind::Observation,
        "event" => MemoryKind::Event,
        "fact" => MemoryKind::Fact,
        "relationship" => MemoryKind::Relationship,
        "habit" => MemoryKind::Habit,
        "location" => MemoryKind::Location,
        "artifact" => MemoryKind::Artifact,
        _ => MemoryKind::Utterance,
    }
}

const fn sensitivity_str(s: Sensitivity) -> &'static str {
    match s {
        Sensitivity::Public => "public",
        Sensitivity::Private => "private",
        Sensitivity::Secret => "secret",
    }
}

fn sensitivity_from_str(s: &str) -> Sensitivity {
    match s {
        "public" => Sensitivity::Public,
        // Anything unrecognised is treated as the most restrictive level. A
        // corrupted or future value must not silently downgrade a memory into
        // something the egress gate would let out.
        "private" => Sensitivity::Private,
        _ => Sensitivity::Secret,
    }
}

/// The stored form of a trust level.
const fn trust_str(t: TrustLevel) -> &'static str {
    match t {
        TrustLevel::FirstParty => "first_party",
        TrustLevel::SelfReported => "self_reported",
        TrustLevel::ThirdParty => "third_party",
    }
}

/// Reads a stored trust level.
///
/// An unrecognised value reads as `ThirdParty`: the strictest level, so a row
/// written by a newer build is treated as hostile input rather than as the
/// user's own voice (THREAT_MODEL §T7).
fn trust_from_str(s: &str) -> TrustLevel {
    match s {
        "first_party" => TrustLevel::FirstParty,
        "self_reported" => TrustLevel::SelfReported,
        _ => TrustLevel::ThirdParty,
    }
}

/// A source about to be written.
///
/// Grouped rather than passed as seven arguments: the two policy fields are the
/// ones that matter, and a positional call site made it easy to swap them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NewSourceRow<'a> {
    /// Its identifier, used only if no source is already configured this way.
    pub id: SourceId,
    /// The adapter kind tag.
    pub kind_tag: &'a str,
    /// Its configuration, which will be sealed.
    pub config: &'a str,
    /// How its content is trusted. A security control, not a quality score.
    pub trust: TrustLevel,
    /// The sensitivity floor its memories carry.
    pub sensitivity: Sensitivity,
}

/// A configured source, as stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredSource {
    /// Its identifier.
    pub id: SourceId,
    /// The adapter kind tag it registers under.
    pub kind_tag: String,
    /// How its content is trusted.
    pub trust: TrustLevel,
    /// The sensitivity floor applied to its memories.
    pub default_sensitivity: Sensitivity,
    /// Whether it is pulled.
    pub enabled: bool,
    /// Its resumable position, as stored JSON.
    pub cursor_json: String,
    /// Its configuration, decrypted.
    ///
    /// A path or a URL, so it is content: it names where a user keeps their
    /// notes. It is sealed at rest and only decrypted for a caller holding the
    /// DEK (I1).
    pub config: String,
}

/// Unused in M0; kept so the query type stays exercised by the compiler.
#[allow(dead_code)]
fn _assert_query_type(_q: &MemoryQuery) {}

/// The encrypted vector index (SPEC Q13).
///
/// Brute-force cosine over sealed rows. See [`crate::vector`] for why an ANN
/// extension is not an option here and what the scan costs.
impl crate::vector::VectorIndex for SqliteStore {
    fn upsert(
        &self,
        dek: &Dek,
        memory: MemoryId,
        embedding: &[f32],
        id: ghostr_core::ids::VectorId,
        nonce: [u8; 24],
    ) -> crate::Result<ghostr_core::ids::VectorId> {
        let expected = self.vector_dimensions()?;
        let found = u32::try_from(embedding.len()).unwrap_or(u32::MAX);
        if expected != 0 && found != expected {
            return Err(crate::Error::VectorDimensionMismatch { found, expected });
        }
        let unit =
            crate::vector::normalize(embedding).ok_or(crate::Error::VectorDimensionMismatch {
                found: 0,
                expected: found,
            })?;

        let mut plaintext = Vec::with_capacity(unit.len() * 4);
        for value in &unit {
            plaintext.extend_from_slice(&value.to_le_bytes());
        }
        let aad = format!("vector:{memory}");
        let sealed = seal_row(dek, &plaintext, &nonce, aad.as_bytes())?;

        self.conn
            .execute(
                "INSERT INTO vector (memory_id, id, dims, nonce, sealed)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(memory_id) DO UPDATE SET
                     id = excluded.id, dims = excluded.dims,
                     nonce = excluded.nonce, sealed = excluded.sealed",
                params![
                    memory.to_string(),
                    id.to_string(),
                    i64::from(found),
                    nonce.to_vec(),
                    sealed
                ],
            )
            .map_err(|_| crate::Error::Backend {
                operation: "upsert vector",
            })?;

        // First vector in an empty index settles its width.
        if expected == 0 {
            self.set_meta(meta_key::VECTOR_DIMENSIONS, &found.to_string())?;
        }
        Ok(id)
    }

    fn knn(
        &self,
        dek: &Dek,
        query: &[f32],
        k: u32,
        filter: &crate::vector::VectorFilter,
    ) -> crate::Result<Vec<crate::vector::Neighbor>> {
        let expected = self.vector_dimensions()?;
        let found = u32::try_from(query.len()).unwrap_or(u32::MAX);
        if expected == 0 {
            return Ok(Vec::new());
        }
        if found != expected {
            return Err(crate::Error::VectorDimensionMismatch { found, expected });
        }
        let Some(unit) = crate::vector::normalize(query) else {
            return Ok(Vec::new());
        };

        let only: std::collections::BTreeSet<String> =
            filter.only.iter().map(ToString::to_string).collect();
        let exclude: std::collections::BTreeSet<String> =
            filter.exclude.iter().map(ToString::to_string).collect();

        let mut statement = self
            .conn
            .prepare("SELECT memory_id, nonce, sealed FROM vector WHERE dims = ?1")
            .map_err(|_| crate::Error::Backend {
                operation: "prepare knn scan",
            })?;
        let rows = statement
            .query_map([i64::from(expected)], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, Vec<u8>>(1)?,
                    r.get::<_, Vec<u8>>(2)?,
                ))
            })
            .map_err(|_| crate::Error::Backend {
                operation: "scan vectors",
            })?;

        let mut scored: Vec<crate::vector::Neighbor> = Vec::new();
        for row in rows {
            let (memory_id, nonce, sealed) = row.map_err(|_| crate::Error::Backend {
                operation: "read vector row",
            })?;
            if !only.is_empty() && !only.contains(&memory_id) {
                continue;
            }
            if exclude.contains(&memory_id) {
                continue;
            }
            let nonce: [u8; 24] = nonce.try_into().map_err(|_| crate::Error::Backend {
                operation: "vector nonce length",
            })?;
            let aad = format!("vector:{memory_id}");
            let plaintext = open_row(dek, &sealed, &nonce, aad.as_bytes())
                .map_err(|_| crate::Error::RowDecryptFailed { table: "vector" })?;
            let vector = decode_vector(&plaintext)?;
            let similarity = crate::vector::dot(&unit, &vector);
            if filter
                .min_similarity
                .is_some_and(|floor| similarity < floor)
            {
                continue;
            }
            let memory = MemoryId::parse(&memory_id)
                .map_err(|_| crate::Error::RowDecryptFailed { table: "vector" })?;
            scored.push(crate::vector::Neighbor { memory, similarity });
        }

        // Ties break on id so the ordering is total: a retrieval set that
        // varied between two runs over the same corpus would make every
        // downstream prompt non-reproducible.
        scored.sort_by(|a, b| {
            b.similarity
                .partial_cmp(&a.similarity)
                .unwrap_or(core::cmp::Ordering::Equal)
                .then_with(|| a.memory.cmp(&b.memory))
        });
        scored.truncate(k as usize);
        Ok(scored)
    }

    fn remove(&self, memory: MemoryId) -> crate::Result<()> {
        self.conn
            .execute(
                "DELETE FROM vector WHERE memory_id = ?1",
                [memory.to_string()],
            )
            .map_err(|_| crate::Error::Backend {
                operation: "remove vector",
            })?;
        Ok(())
    }

    fn rebuild(
        &self,
        model: &str,
        dimensions: u32,
    ) -> crate::Result<crate::vector::RebuildProgress> {
        self.set_meta(meta_key::VECTOR_MODEL, model)?;
        self.set_meta(meta_key::VECTOR_DIMENSIONS, &dimensions.to_string())?;
        // Vectors already at the new width are kept. That is what makes a
        // rebuild resumable: a lid closing halfway through loses the work still
        // to do, not the work already done.
        self.conn
            .execute(
                "DELETE FROM vector WHERE dims != ?1",
                [i64::from(dimensions)],
            )
            .map_err(|_| crate::Error::Backend {
                operation: "drop stale vectors",
            })?;
        self.rebuild_progress()
    }

    fn unembedded(&self, limit: u32) -> crate::Result<Vec<MemoryId>> {
        let dimensions = self.vector_dimensions()?;
        let mut statement = self
            .conn
            .prepare(
                "SELECT m.id FROM memory m
                 LEFT JOIN vector v ON v.memory_id = m.id AND v.dims = ?1
                 WHERE v.memory_id IS NULL AND m.shredded_at IS NULL
                 ORDER BY m.id
                 LIMIT ?2",
            )
            .map_err(|_| crate::Error::Backend {
                operation: "prepare unembedded query",
            })?;
        let rows = statement
            .query_map(params![i64::from(dimensions), i64::from(limit)], |r| {
                r.get::<_, String>(0)
            })
            .map_err(|_| crate::Error::Backend {
                operation: "query unembedded",
            })?;
        let mut out = Vec::new();
        for row in rows {
            let id = row.map_err(|_| crate::Error::Backend {
                operation: "read unembedded row",
            })?;
            if let Ok(parsed) = MemoryId::parse(&id) {
                out.push(parsed);
            }
        }
        Ok(out)
    }

    fn descriptor(&self) -> crate::Result<crate::vector::IndexDescriptor> {
        let count: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM vector", [], |r| r.get(0))
            .map_err(|_| crate::Error::Backend {
                operation: "count vectors",
            })?;
        Ok(crate::vector::IndexDescriptor {
            model: self.meta(meta_key::VECTOR_MODEL)?.unwrap_or_default(),
            dimensions: self.vector_dimensions()?,
            count: count.unsigned_abs(),
        })
    }
}

impl SqliteStore {
    /// The index's declared width, or `0` if nothing has set one yet.
    fn vector_dimensions(&self) -> crate::Result<u32> {
        Ok(self
            .meta(meta_key::VECTOR_DIMENSIONS)?
            .and_then(|v| v.parse::<u32>().ok())
            .unwrap_or(0))
    }

    /// How much of the index is built, against how much needs to be.
    fn rebuild_progress(&self) -> crate::Result<crate::vector::RebuildProgress> {
        let dimensions = self.vector_dimensions()?;
        let completed: i64 = self
            .conn
            .query_row(
                "SELECT COUNT(*) FROM vector WHERE dims = ?1",
                [i64::from(dimensions)],
                |r| r.get(0),
            )
            .map_err(|_| crate::Error::Backend {
                operation: "count current vectors",
            })?;
        let total: i64 = self
            .conn
            .query_row(
                "SELECT COUNT(*) FROM memory WHERE shredded_at IS NULL",
                [],
                |r| r.get(0),
            )
            .map_err(|_| crate::Error::Backend {
                operation: "count memories",
            })?;
        Ok(crate::vector::RebuildProgress {
            completed: completed.unsigned_abs(),
            total: total.unsigned_abs(),
        })
    }
}

/// Reads a stored vector back out of its little-endian bytes.
fn decode_vector(bytes: &[u8]) -> crate::Result<Vec<f32>> {
    if !bytes.len().is_multiple_of(4) {
        return Err(crate::Error::RowDecryptFailed { table: "vector" });
    }
    Ok(bytes
        .chunks_exact(4)
        .map(|c| f32::from_le_bytes([c[0], c[1], c[2], c[3]]))
        .collect())
}

/// Fixtures shared by this file's test modules.
#[cfg(test)]
mod tests_support {
    use ghostr_core::memory::MemoryBody;
    use ghostr_crypto::kdf::derive_dek;

    use super::*;

    pub(super) fn dek() -> Dek {
        derive_dek(&[42u8; 32])
    }

    pub(super) fn store(dir: &Path) -> SqliteStore {
        let s = SqliteStore::open(dir).expect("open");
        let dek = dek();
        s.upsert_source(
            &dek,
            SourceId::new(1, [0u8; 10]),
            "markdown_vault",
            "{}",
            [0u8; 24],
        )
        .expect("source");
        s
    }

    pub(super) fn memory(source: SourceId, n: u8, text: &str) -> Memory {
        let id = MemoryId::new(1_700_000_000_000 + u64::from(n), [n; 10]);
        Memory {
            id,
            source_id: source,
            occurred_at: Some(Timestamp::new(1_700_000_000_000, 0)),
            ingested_at: Timestamp::new(1_700_000_000_000, 0),
            kind: MemoryKind::Utterance,
            body: MemoryBody {
                text: text.to_owned(),
                structured: None,
                redactions: Vec::new(),
            },
            entities: Vec::new(),
            salience: 0.5,
            sensitivity: Sensitivity::Private,
            provenance: Provenance {
                source_id: source,
                external_id: Some(format!("note-{n}.md")),
                url: None,
                raw_hash: ghostr_core::hash::tagged_hash(ghostr_core::hash::Tag::MemoryLeaf, &[n]),
            },
            salt: [n; 32],
            supersedes: None,
            embedding: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use ghostr_crypto::kdf::derive_dek;

    use super::tests_support::{dek, memory, store};
    use super::*;

    /// Deliberately long words.
    ///
    /// The absence assertions below scan raw ciphertext, where a three-letter
    /// needle turns up by chance often enough to fail CI on a database that
    /// leaked nothing. Every needle here is a whole word or longer.
    const SECRET_TEXT: &str = "met Nanthawan at the tea shop and finally fixed the timezone bug";

    #[test]
    fn memory_round_trips_through_encryption() {
        let dir = tempfile::tempdir().expect("tempdir");
        let s = store(dir.path());
        let src = SourceId::new(1, [0u8; 10]);
        let m = memory(src, 1, SECRET_TEXT);
        s.put_memory(&dek(), &m, [1u8; 24]).expect("put");

        let back = s.get_memory(&dek(), m.id).expect("get").expect("present");
        assert_eq!(back.body.text, SECRET_TEXT);
        assert_eq!(back.salt, m.salt);
        assert_eq!(back.sensitivity, Sensitivity::Private);
    }

    /// SPEC I1: nothing readable on disk without the key.
    ///
    /// Reads the raw database bytes — WAL included, since a checkpoint may not
    /// have run — and asserts no fragment of the note appears anywhere.
    #[test]
    fn no_plaintext_content_appears_in_the_database_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        {
            let s = store(dir.path());
            let src = SourceId::new(1, [0u8; 10]);
            for n in 0..5u8 {
                s.put_memory(&dek(), &memory(src, n, SECRET_TEXT), [n; 24])
                    .expect("put");
            }
        }

        let mut raw = Vec::new();
        for entry in std::fs::read_dir(dir.path()).expect("read dir").flatten() {
            raw.extend(std::fs::read(entry.path()).unwrap_or_default());
        }
        assert!(!raw.is_empty(), "database should not be empty");

        let needles = ["Nanthawan", "tea shop", "timezone bug", SECRET_TEXT];
        for needle in needles {
            assert!(
                !raw.windows(needle.len()).any(|w| w == needle.as_bytes()),
                "plaintext `{needle}` found in the database file"
            );
        }
    }

    #[test]
    fn wrong_key_cannot_read_a_memory() {
        let dir = tempfile::tempdir().expect("tempdir");
        let s = store(dir.path());
        let src = SourceId::new(1, [0u8; 10]);
        let m = memory(src, 1, SECRET_TEXT);
        s.put_memory(&dek(), &m, [1u8; 24]).expect("put");

        let other = derive_dek(&[43u8; 32]);
        assert!(matches!(
            s.get_memory(&other, m.id),
            Err(crate::Error::RowDecryptFailed { .. })
        ));
    }

    #[test]
    fn duplicate_raw_hash_is_rejected_so_ingest_is_idempotent() {
        let dir = tempfile::tempdir().expect("tempdir");
        let s = store(dir.path());
        let src = SourceId::new(1, [0u8; 10]);
        let first = memory(src, 7, SECRET_TEXT);
        s.put_memory(&dek(), &first, [1u8; 24]).expect("put");

        assert!(
            s.has_raw_hash(src, first.provenance.raw_hash)
                .expect("check")
        );

        // Same source, same raw content, different id: the unique index must
        // reject it, which is what makes re-running `ingest` a no-op.
        let mut second = memory(src, 8, SECRET_TEXT);
        second.provenance.raw_hash = first.provenance.raw_hash;
        assert!(matches!(
            s.put_memory(&dek(), &second, [2u8; 24]),
            Err(crate::Error::AppendOnlyViolation { .. })
        ));
    }

    #[test]
    fn shredding_removes_content_but_keeps_the_row() {
        let dir = tempfile::tempdir().expect("tempdir");
        let s = store(dir.path());
        let src = SourceId::new(1, [0u8; 10]);
        let m = memory(src, 1, SECRET_TEXT);
        s.put_memory(&dek(), &m, [1u8; 24]).expect("put");

        s.shred(m.id, RedactionReason::UserRequest, Timestamp::new(1, 0))
            .expect("shred");
        assert!(matches!(
            s.get_memory(&dek(), m.id),
            Err(crate::Error::Shredded { .. })
        ));
        // The row survives, so the chain still has something to point at.
        assert_eq!(s.memory_count().expect("count"), 1);
    }

    #[test]
    fn shredding_an_unknown_memory_is_an_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        let s = store(dir.path());
        let missing = MemoryId::new(1, [9u8; 10]);
        assert!(matches!(
            s.shred(missing, RedactionReason::UserRequest, Timestamp::new(1, 0)),
            Err(crate::Error::MemoryNotFound { .. })
        ));
    }

    /// SPEC I2: a sealed footage is immutable, enforced by the schema rather
    /// than by application code — because the application is what might be wrong.
    #[test]
    fn the_schema_refuses_to_update_or_delete_sealed_footage() {
        let dir = tempfile::tempdir().expect("tempdir");
        let s = SqliteStore::open(dir.path()).expect("open");
        s.conn
            .execute(
                "INSERT INTO footage
                 (seq, date, tz, window_start, window_end, empty, merkle_root, prev_link,
                  link, leaf_count, sealed_at, sealed_off, body_nonce, body_sealed)
                 VALUES (1,'2026-01-01','UTC',0,1,1,'aa','bb','cc',1,0,0,x'00',x'00')",
                [],
            )
            .expect("insert");

        assert!(
            s.conn
                .execute("UPDATE footage SET link = 'dd' WHERE seq = 1", [])
                .is_err()
        );
        assert!(
            s.conn
                .execute("DELETE FROM footage WHERE seq = 1", [])
                .is_err()
        );
    }

    #[test]
    fn window_uses_occurred_at_and_excludes_the_upper_bound() {
        let dir = tempfile::tempdir().expect("tempdir");
        let s = store(dir.path());
        let src = SourceId::new(1, [0u8; 10]);

        for (n, at) in [(1u8, 1_000i64), (2, 2_000), (3, 3_000)] {
            let mut m = memory(src, n, SECRET_TEXT);
            m.occurred_at = Some(Timestamp::new(at, 0));
            s.put_memory(&dek(), &m, [n; 24]).expect("put");
        }

        // Half-open: 1_000 is included, 3_000 is not.
        let got = s
            .window(
                &dek(),
                TimeRange {
                    start: Timestamp::new(1_000, 0),
                    end: Timestamp::new(3_000, 0),
                },
            )
            .expect("window");
        assert_eq!(got.len(), 2);
    }

    // --- entities (M1) ---------------------------------------------------

    fn entity_id(n: u8) -> ghostr_core::ids::EntityId {
        ghostr_core::ids::EntityId::new(u64::from(n), [n; 10])
    }

    #[test]
    fn resolving_the_same_name_twice_returns_one_entity() {
        let dir = tempfile::tempdir().expect("tempdir");
        let s = store(dir.path());
        let d = dek();
        let now = Timestamp::new(1_000, 0);

        let a = s
            .resolve_entity(
                &d,
                "Nan",
                crate::entity::EntityKind::Person,
                now,
                entity_id(1),
                [1u8; 24],
            )
            .expect("first");
        // Different case and whitespace: the same person, and resolution that
        // missed on that would be worse than none.
        let b = s
            .resolve_entity(
                &d,
                "  nan ",
                crate::entity::EntityKind::Person,
                now,
                entity_id(2),
                [2u8; 24],
            )
            .expect("second");

        assert_eq!(a.id, b.id);
        assert_eq!(a.pseudonym, b.pseudonym);
        assert_eq!(s.all_entities(&d).expect("list").len(), 1);
    }

    #[test]
    fn pseudonyms_are_sequential_and_stable() {
        let dir = tempfile::tempdir().expect("tempdir");
        let s = store(dir.path());
        let d = dek();
        let now = Timestamp::new(1_000, 0);

        let a = s
            .resolve_entity(
                &d,
                "Nan",
                crate::entity::EntityKind::Person,
                now,
                entity_id(1),
                [1u8; 24],
            )
            .expect("a");
        let b = s
            .resolve_entity(
                &d,
                "Somchai",
                crate::entity::EntityKind::Person,
                now,
                entity_id(2),
                [2u8; 24],
            )
            .expect("b");
        assert_eq!(a.pseudonym, "Person A");
        assert_eq!(b.pseudonym, "Person B");

        // Stable across a re-resolve: a model must be able to follow "Person A"
        // through a conversation.
        let again = s
            .resolve_entity(
                &d,
                "Nan",
                crate::entity::EntityKind::Person,
                now,
                entity_id(3),
                [3u8; 24],
            )
            .expect("again");
        assert_eq!(again.pseudonym, "Person A");
    }

    #[test]
    fn kinds_get_separate_pseudonym_sequences() {
        let dir = tempfile::tempdir().expect("tempdir");
        let s = store(dir.path());
        let d = dek();
        let now = Timestamp::new(1_000, 0);
        let p = s
            .resolve_entity(
                &d,
                "Nan",
                crate::entity::EntityKind::Person,
                now,
                entity_id(1),
                [1u8; 24],
            )
            .expect("person");
        let pl = s
            .resolve_entity(
                &d,
                "Bangkok",
                crate::entity::EntityKind::Place,
                now,
                entity_id(2),
                [2u8; 24],
            )
            .expect("place");
        assert_eq!(p.pseudonym, "Person A");
        assert_eq!(pl.pseudonym, "Place A");
    }

    /// The entity table is the highest-value target after the corpus itself: it
    /// is what turns "Person A appears daily" into a name (THREAT_MODEL §T10).
    #[test]
    fn entity_names_are_not_readable_on_disk() {
        let dir = tempfile::tempdir().expect("tempdir");
        {
            let s = store(dir.path());
            let d = dek();
            for (n, name) in [(1u8, "Nan"), (2, "Somchai"), (3, "Ploy")] {
                s.resolve_entity(
                    &d,
                    name,
                    crate::entity::EntityKind::Person,
                    Timestamp::new(1_000, 0),
                    entity_id(n),
                    [n; 24],
                )
                .expect("resolve");
            }
        }
        let mut raw = Vec::new();
        for entry in std::fs::read_dir(dir.path()).expect("read dir").flatten() {
            raw.extend(std::fs::read(entry.path()).unwrap_or_default());
        }
        for name in ["Nan", "Somchai", "Ploy"] {
            assert!(
                !raw.windows(name.len()).any(|w| w == name.as_bytes()),
                "entity name `{name}` is readable on disk"
            );
        }
        // The pseudonym is not secret and is expected to be present.
        assert!(raw.windows(8).any(|w| w == b"Person A"));
    }

    /// The lookup index must not be attackable with a dictionary of names.
    #[test]
    fn the_name_tag_is_keyed_to_the_vault() {
        let dir = tempfile::tempdir().expect("tempdir");
        let s = store(dir.path());
        let mine = s.name_tag(&dek(), "Nan").expect("tag");
        let theirs = s.name_tag(&derive_dek(&[99u8; 32]), "Nan").expect("tag");
        assert_ne!(mine, theirs, "two vaults must not share a tag for one name");
        // Deterministic within a vault, or resolution would create a new entity
        // on every mention.
        assert_eq!(mine, s.name_tag(&dek(), "Nan").expect("tag"));
    }

    #[test]
    fn memories_link_to_entities_for_forget() {
        let dir = tempfile::tempdir().expect("tempdir");
        let s = store(dir.path());
        let d = dek();
        let src = SourceId::new(1, [0u8; 10]);
        let m = memory(src, 1, SECRET_TEXT);
        s.put_memory(&d, &m, [1u8; 24]).expect("put");
        let e = s
            .resolve_entity(
                &d,
                "Nan",
                crate::entity::EntityKind::Person,
                Timestamp::new(1, 0),
                entity_id(1),
                [1u8; 24],
            )
            .expect("entity");
        s.link_memory_entity(m.id, e.id).expect("link");
        assert_eq!(s.memories_for_entity(e.id).expect("lookup"), vec![m.id]);
    }

    #[test]
    fn spreadsheet_labels_roll_over_past_z() {
        assert_eq!(spreadsheet_label(0), "A");
        assert_eq!(spreadsheet_label(25), "Z");
        assert_eq!(spreadsheet_label(26), "AA");
        assert_eq!(spreadsheet_label(51), "AZ");
    }

    // --- egress log + migration (M1) ---------------------------------------

    fn record(provider: &str, decision: &str) -> EgressRecord {
        EgressRecord {
            at: Timestamp::new(1_000, 0),
            provider: provider.to_owned(),
            task: "extraction".to_owned(),
            decision: decision.to_owned(),
            deny_reason: (decision == "deny").then(|| "secret_content".to_owned()),
            policy_id: "standard/v1".to_owned(),
            bytes_sent: if decision == "deny" { 0 } else { 128 },
            payload_digest: (decision != "deny").then(|| "ab".repeat(32)),
            entities: 2,
        }
    }

    #[test]
    fn egress_records_round_trip_in_order() {
        let dir = tempfile::tempdir().expect("tempdir");
        let s = SqliteStore::open(dir.path()).expect("open");
        s.append_egress(&record("acme", "allow_redacted"))
            .expect("append");
        s.append_egress(&record("acme", "deny")).expect("append");

        let all = s.egress_since(Timestamp::new(0, 0)).expect("read");
        assert_eq!(all.len(), 2);
        // Denials are recorded too: a log of only the allows cannot show that
        // the system refused anything (SPEC I5).
        assert_eq!(all[1].decision, "deny");
        assert_eq!(all[1].deny_reason.as_deref(), Some("secret_content"));
        assert_eq!(all[1].bytes_sent, 0);
    }

    /// An audit record that can be edited is not an audit record.
    #[test]
    fn the_egress_log_is_append_only() {
        let dir = tempfile::tempdir().expect("tempdir");
        let s = SqliteStore::open(dir.path()).expect("open");
        s.append_egress(&record("acme", "allow_redacted"))
            .expect("append");
        assert!(
            s.conn
                .execute("UPDATE egress_log SET bytes_sent = 0", [])
                .is_err()
        );
        assert!(s.conn.execute("DELETE FROM egress_log", []).is_err());
    }

    /// The log must not become a second copy of the corpus.
    ///
    /// `EgressRecord` has no payload field today, so this is a tripwire rather
    /// than a leak test: it fires the day somebody adds a column that carries
    /// the text a digest stands for.
    #[test]
    fn the_egress_log_stores_a_digest_not_a_payload() {
        /// What the record's digest is a digest *of*.
        const PAYLOAD: &str = "met Nanthawan at the tea shop";

        let dir = tempfile::tempdir().expect("tempdir");
        let s = SqliteStore::open(dir.path()).expect("open");
        s.append_egress(&record("acme", "allow_redacted"))
            .expect("append");
        let raw = std::fs::read(dir.path().join(DB_FILENAME)).expect("read");
        assert!(
            !raw.windows(PAYLOAD.len()).any(|w| w == PAYLOAD.as_bytes()),
            "the egress log carries the payload, not just its digest"
        );
        // The digest is present and is what a user would compare against.
        let back = s.egress_since(Timestamp::new(0, 0)).expect("read");
        assert_eq!(
            back[0].payload_digest.as_deref(),
            Some("ab".repeat(32).as_str())
        );
    }

    /// A vault created by M0 at schema v1 must upgrade, not fail to open.
    #[test]
    fn a_v1_vault_migrates_to_the_current_schema() {
        let dir = tempfile::tempdir().expect("tempdir");
        {
            // Build a v1 database by hand: schema v1 only, version stamped 1.
            let conn = rusqlite::Connection::open(dir.path().join(DB_FILENAME)).expect("open");
            conn.execute_batch(crate::schema::SCHEMA_V1)
                .expect("v1 schema");
            conn.execute(
                "INSERT INTO meta (key, value) VALUES (?1, '1')",
                [crate::schema::meta_key::SCHEMA_VERSION],
            )
            .expect("stamp");
        }

        let s = SqliteStore::open(dir.path()).expect("migrate on open");
        assert_eq!(
            s.meta(crate::schema::meta_key::SCHEMA_VERSION)
                .expect("meta")
                .as_deref(),
            Some(SCHEMA_VERSION.to_string().as_str())
        );
        // Every table added since v1 exists and works.
        s.append_egress(&record("acme", "allow_redacted"))
            .expect("append after migration");
        assert_eq!(s.egress_count().expect("count"), 1);
        use crate::vector::VectorIndex as _;
        assert_eq!(s.descriptor().expect("vector descriptor").count, 0);
        // v5: the persona table exists.
        assert!(s.persona_history(10).expect("history").is_empty());
        // v4: two vaults at different paths are two sources.
        let d = dek();
        let a = s
            .upsert_source(
                &d,
                SourceId::new(2, [2u8; 10]),
                "markdown_vault",
                "/a",
                [2u8; 24],
            )
            .expect("first vault");
        let b = s
            .upsert_source(
                &d,
                SourceId::new(3, [3u8; 10]),
                "markdown_vault",
                "/b",
                [3u8; 24],
            )
            .expect("second vault");
        assert_ne!(a, b);
    }

    #[test]
    fn migration_is_idempotent_across_reopens() {
        let dir = tempfile::tempdir().expect("tempdir");
        for _ in 0..3 {
            let s = SqliteStore::open(dir.path()).expect("open");
            s.append_egress(&record("acme", "allow_redacted"))
                .expect("append");
        }
        assert_eq!(
            SqliteStore::open(dir.path())
                .expect("open")
                .egress_count()
                .expect("count"),
            3
        );
    }

    #[test]
    fn a_newer_schema_is_refused_rather_than_guessed_at() {
        let dir = tempfile::tempdir().expect("tempdir");
        {
            let s = SqliteStore::open(dir.path()).expect("open");
            s.set_meta(crate::schema::meta_key::SCHEMA_VERSION, "999")
                .expect("bump");
        }
        assert!(matches!(
            SqliteStore::open(dir.path()),
            Err(crate::Error::SchemaTooNew { found: 999, .. })
        ));
    }
}

// ---------------------------------------------------------------------------
// Entities (M1)
// ---------------------------------------------------------------------------

/// A resolved entity, as stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredEntity {
    /// Stable identifier.
    pub id: ghostr_core::ids::EntityId,
    /// Canonical name. Encrypted at rest; never egresses.
    pub name: String,
    /// What sort of thing this is.
    pub kind: crate::entity::EntityKind,
    /// Stable pseudonym used at the egress boundary.
    pub pseudonym: String,
    /// When first seen.
    pub first_seen: Timestamp,
    /// When last referenced.
    pub last_seen: Timestamp,
}

impl SqliteStore {
    /// Resolves a name to an entity, creating one if it is unknown.
    ///
    /// Lookup is by a **keyed digest of the normalised name**, not by the
    /// plaintext. The name column is ciphertext, so a plaintext lookup would
    /// mean decrypting every row on every mention. The digest is keyed by the
    /// DEK, so the index leaks nothing to someone holding the file: without the
    /// key it is 32 random-looking bytes, and it cannot be dictionary-attacked
    /// the way a bare `SHA256(name)` could.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Backend`](crate::Error::Backend) if the write fails.
    pub fn resolve_entity(
        &self,
        dek: &Dek,
        name: &str,
        kind: crate::entity::EntityKind,
        now: Timestamp,
        new_id: ghostr_core::ids::EntityId,
        nonce: [u8; 24],
    ) -> crate::Result<StoredEntity> {
        let tag = self.name_tag(dek, name)?;

        if let Some(existing) = self.entity_by_tag(dek, &tag)? {
            self.conn
                .execute(
                    "UPDATE entity SET last_seen = ?2 WHERE id = ?1",
                    params![existing.id.to_string(), now.utc_millis()],
                )
                .map_err(|_| crate::Error::Backend {
                    operation: "touch entity",
                })?;
            return Ok(StoredEntity {
                last_seen: now,
                ..existing
            });
        }

        let pseudonym = self.next_pseudonym(kind)?;
        let aad = format!("entity:{new_id}");
        let sealed = seal_row(dek, name.trim().as_bytes(), &nonce, aad.as_bytes())?;

        self.conn
            .execute(
                "INSERT INTO entity
                 (id, kind, pseudonym, first_seen, last_seen, name_nonce, name_sealed, name_tag)
                 VALUES (?1, ?2, ?3, ?4, ?4, ?5, ?6, ?7)",
                params![
                    new_id.to_string(),
                    entity_kind_str(kind),
                    pseudonym,
                    now.utc_millis(),
                    nonce.to_vec(),
                    sealed,
                    tag,
                ],
            )
            .map_err(|_| crate::Error::Backend {
                operation: "insert entity",
            })?;

        Ok(StoredEntity {
            id: new_id,
            name: name.trim().to_owned(),
            kind,
            pseudonym,
            first_seen: now,
            last_seen: now,
        })
    }

    /// Reads one entity.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Backend`](crate::Error::Backend) if the read fails.
    pub fn get_entity(
        &self,
        dek: &Dek,
        id: ghostr_core::ids::EntityId,
    ) -> crate::Result<Option<StoredEntity>> {
        let row = self
            .conn
            .query_row(
                "SELECT id, kind, pseudonym, first_seen, last_seen, name_nonce, name_sealed
                 FROM entity WHERE id = ?1",
                [id.to_string()],
                |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, String>(2)?,
                        r.get::<_, i64>(3)?,
                        r.get::<_, i64>(4)?,
                        r.get::<_, Vec<u8>>(5)?,
                        r.get::<_, Vec<u8>>(6)?,
                    ))
                },
            )
            .optional()
            .map_err(|_| crate::Error::Backend {
                operation: "read entity",
            })?;
        row.map(|r| self.decrypt_entity(dek, r)).transpose()
    }

    /// Every entity, ordered by pseudonym so listings are stable.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Backend`](crate::Error::Backend) if the read fails.
    pub fn all_entities(&self, dek: &Dek) -> crate::Result<Vec<StoredEntity>> {
        let rows: Vec<_> = {
            let mut stmt = self
                .conn
                .prepare(
                    "SELECT id, kind, pseudonym, first_seen, last_seen, name_nonce, name_sealed
                     FROM entity ORDER BY pseudonym",
                )
                .map_err(|_| crate::Error::Backend {
                    operation: "prepare entity list",
                })?;
            let mapped = stmt
                .query_map([], |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, String>(2)?,
                        r.get::<_, i64>(3)?,
                        r.get::<_, i64>(4)?,
                        r.get::<_, Vec<u8>>(5)?,
                        r.get::<_, Vec<u8>>(6)?,
                    ))
                })
                .map_err(|_| crate::Error::Backend {
                    operation: "list entities",
                })?;
            mapped
                .collect::<Result<_, _>>()
                .map_err(|_| crate::Error::Backend {
                    operation: "collect entities",
                })?
        };
        rows.into_iter()
            .map(|r| self.decrypt_entity(dek, r))
            .collect()
    }

    /// Links a memory to an entity.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Backend`](crate::Error::Backend) if the write fails.
    pub fn link_memory_entity(
        &self,
        memory: MemoryId,
        entity: ghostr_core::ids::EntityId,
    ) -> crate::Result<()> {
        self.conn
            .execute(
                "INSERT OR IGNORE INTO memory_entity (memory_id, entity_id) VALUES (?1, ?2)",
                params![memory.to_string(), entity.to_string()],
            )
            .map_err(|_| crate::Error::Backend {
                operation: "link memory to entity",
            })?;
        Ok(())
    }

    /// Every memory referencing an entity. Backs `ghostr forget <person>`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Backend`](crate::Error::Backend) if the read fails.
    pub fn memories_for_entity(
        &self,
        entity: ghostr_core::ids::EntityId,
    ) -> crate::Result<Vec<MemoryId>> {
        let mut stmt = self
            .conn
            .prepare("SELECT memory_id FROM memory_entity WHERE entity_id = ?1 ORDER BY memory_id")
            .map_err(|_| crate::Error::Backend {
                operation: "prepare entity memories",
            })?;
        let rows = stmt
            .query_map([entity.to_string()], |r| r.get::<_, String>(0))
            .map_err(|_| crate::Error::Backend {
                operation: "read entity memories",
            })?;
        let mut out = Vec::new();
        for row in rows {
            let id = row.map_err(|_| crate::Error::Backend {
                operation: "entity memory row",
            })?;
            out.push(MemoryId::parse(&id).map_err(|_| crate::Error::Backend {
                operation: "parse entity memory id",
            })?);
        }
        Ok(out)
    }

    /// The keyed lookup digest for a name.
    ///
    /// Keyed by the DEK via HMAC, so two vaults holding the same name produce
    /// different tags and the index cannot be attacked with a name dictionary.
    fn name_tag(&self, dek: &Dek, name: &str) -> crate::Result<String> {
        // Normalise first: "  Nan " and "nan" are the same person, and entity
        // resolution that misses on whitespace is worse than none.
        let normalised = name.trim().to_lowercase();
        // The DEK is not exposed as bytes, so the tag is derived by sealing a
        // fixed nonce and hashing the result. Deterministic because the nonce
        // and AAD are fixed, and unforgeable without the key.
        let sealed = seal_row(dek, normalised.as_bytes(), &[0u8; 24], b"entity-name-tag")?;
        Ok(ghostr_core::hash::tagged_hash(ghostr_core::hash::Tag::MetaLeaf, &sealed).to_hex())
    }

    fn entity_by_tag(&self, dek: &Dek, tag: &str) -> crate::Result<Option<StoredEntity>> {
        let row = self
            .conn
            .query_row(
                "SELECT id, kind, pseudonym, first_seen, last_seen, name_nonce, name_sealed
                 FROM entity WHERE name_tag = ?1",
                [tag],
                |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, String>(2)?,
                        r.get::<_, i64>(3)?,
                        r.get::<_, i64>(4)?,
                        r.get::<_, Vec<u8>>(5)?,
                        r.get::<_, Vec<u8>>(6)?,
                    ))
                },
            )
            .optional()
            .map_err(|_| crate::Error::Backend {
                operation: "look up entity by tag",
            })?;
        row.map(|r| self.decrypt_entity(dek, r)).transpose()
    }

    /// Allocates the next pseudonym for a kind: `Person A`, `Person B`, …
    ///
    /// Sequential and stable. A remote model can follow "Person A" through a
    /// conversation without ever learning who that is, and the same person keeps
    /// the same pseudonym across sessions (SPEC §11.2).
    fn next_pseudonym(&self, kind: crate::entity::EntityKind) -> crate::Result<String> {
        let count: i64 = self
            .conn
            .query_row(
                "SELECT COUNT(*) FROM entity WHERE kind = ?1",
                [entity_kind_str(kind)],
                |r| r.get(0),
            )
            .map_err(|_| crate::Error::Backend {
                operation: "count entities",
            })?;
        Ok(format!(
            "{} {}",
            entity_kind_label(kind),
            spreadsheet_label(count.max(0).unsigned_abs())
        ))
    }

    fn decrypt_entity(
        &self,
        dek: &Dek,
        row: (String, String, String, i64, i64, Vec<u8>, Vec<u8>),
    ) -> crate::Result<StoredEntity> {
        let (id, kind, pseudonym, first_seen, last_seen, nonce, sealed) = row;
        let id = ghostr_core::ids::EntityId::parse(&id).map_err(|_| crate::Error::Backend {
            operation: "parse entity id",
        })?;
        let nonce: [u8; 24] = nonce.try_into().map_err(|_| crate::Error::Backend {
            operation: "entity nonce length",
        })?;
        let aad = format!("entity:{id}");
        let name = open_row(dek, &sealed, &nonce, aad.as_bytes())
            .map_err(|_| crate::Error::RowDecryptFailed { table: "entity" })?;
        Ok(StoredEntity {
            id,
            name: String::from_utf8(name)
                .map_err(|_| crate::Error::RowDecryptFailed { table: "entity" })?,
            kind: entity_kind_from_str(&kind),
            pseudonym,
            first_seen: Timestamp::new(first_seen, 0),
            last_seen: Timestamp::new(last_seen, 0),
        })
    }
}

/// `0 -> A`, `25 -> Z`, `26 -> AA`, in the manner of spreadsheet columns.
///
/// Pseudonyms have to stay short and readable in a prompt, and a user with more
/// than 26 people in their corpus is ordinary rather than exceptional.
fn spreadsheet_label(mut n: u64) -> String {
    let mut out = Vec::new();
    loop {
        out.push(b'A' + u8::try_from(n % 26).unwrap_or(0));
        if n < 26 {
            break;
        }
        n = n / 26 - 1;
    }
    out.reverse();
    String::from_utf8(out).unwrap_or_else(|_| "A".to_owned())
}

const fn entity_kind_str(kind: crate::entity::EntityKind) -> &'static str {
    match kind {
        crate::entity::EntityKind::Person => "person",
        crate::entity::EntityKind::Place => "place",
        crate::entity::EntityKind::Project => "project",
        crate::entity::EntityKind::Organisation => "organisation",
    }
}

const fn entity_kind_label(kind: crate::entity::EntityKind) -> &'static str {
    match kind {
        crate::entity::EntityKind::Person => "Person",
        crate::entity::EntityKind::Place => "Place",
        crate::entity::EntityKind::Project => "Project",
        crate::entity::EntityKind::Organisation => "Org",
    }
}

fn entity_kind_from_str(s: &str) -> crate::entity::EntityKind {
    match s {
        "place" => crate::entity::EntityKind::Place,
        "project" => crate::entity::EntityKind::Project,
        "organisation" => crate::entity::EntityKind::Organisation,
        _ => crate::entity::EntityKind::Person,
    }
}

// ---------------------------------------------------------------------------
// The egress audit log (M1)
// ---------------------------------------------------------------------------

/// One recorded egress decision.
///
/// Holds no content: a provider, a task, a decision, a byte count, and a digest.
/// Storing the payload would recreate the corpus inside the audit log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EgressRecord {
    /// When.
    pub at: Timestamp,
    /// Where to.
    pub provider: String,
    /// What for.
    pub task: String,
    /// `allow`, `allow_redacted`, or `deny`.
    pub decision: String,
    /// Why, when the decision was a deny.
    pub deny_reason: Option<String>,
    /// Which policy decided.
    pub policy_id: String,
    /// Bytes actually transmitted. Zero for a deny.
    pub bytes_sent: u32,
    /// Digest of the exact bytes sent, after redaction.
    pub payload_digest: Option<String>,
    /// How many entity names were pseudonymised.
    pub entities: u32,
}

impl SqliteStore {
    /// Appends an egress record.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Backend`](crate::Error::Backend) if the write fails.
    /// Callers must treat that as fatal to the request: an egress that could not
    /// be recorded is the thing the user was told could not happen (SPEC I5).
    pub fn append_egress(&self, record: &EgressRecord) -> crate::Result<()> {
        self.conn
            .execute(
                "INSERT INTO egress_log
                 (at, provider, task, decision, deny_reason, policy_id, bytes_sent,
                  payload_digest, entities)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![
                    record.at.utc_millis(),
                    record.provider,
                    record.task,
                    record.decision,
                    record.deny_reason,
                    record.policy_id,
                    i64::from(record.bytes_sent),
                    record.payload_digest,
                    i64::from(record.entities),
                ],
            )
            .map_err(|_| crate::Error::Backend {
                operation: "append egress record",
            })?;
        Ok(())
    }

    /// Records at or after `from`, oldest first.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Backend`](crate::Error::Backend) if the read fails.
    pub fn egress_since(&self, from: Timestamp) -> crate::Result<Vec<EgressRecord>> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT at, provider, task, decision, deny_reason, policy_id, bytes_sent,
                        payload_digest, entities
                 FROM egress_log WHERE at >= ?1 ORDER BY at, id",
            )
            .map_err(|_| crate::Error::Backend {
                operation: "prepare egress query",
            })?;
        let rows = stmt
            .query_map([from.utc_millis()], |r| {
                Ok(EgressRecord {
                    at: Timestamp::new(r.get::<_, i64>(0)?, 0),
                    provider: r.get(1)?,
                    task: r.get(2)?,
                    decision: r.get(3)?,
                    deny_reason: r.get(4)?,
                    policy_id: r.get(5)?,
                    bytes_sent: u32::try_from(r.get::<_, i64>(6)?).unwrap_or(0),
                    payload_digest: r.get(7)?,
                    entities: u32::try_from(r.get::<_, i64>(8)?).unwrap_or(0),
                })
            })
            .map_err(|_| crate::Error::Backend {
                operation: "read egress log",
            })?;
        rows.collect::<Result<_, _>>()
            .map_err(|_| crate::Error::Backend {
                operation: "collect egress records",
            })
    }

    /// How many records the log holds.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Backend`](crate::Error::Backend) if the read fails.
    pub fn egress_count(&self) -> crate::Result<u64> {
        self.conn
            .query_row("SELECT COUNT(*) FROM egress_log", [], |r| {
                r.get::<_, i64>(0)
            })
            .map(|n| n.max(0).unsigned_abs())
            .map_err(|_| crate::Error::Backend {
                operation: "count egress records",
            })
    }
}

/// Persona versions.
impl SqliteStore {
    /// Writes a version and makes it head.
    ///
    /// The previous head stays stored: a quest issued under v12 is scored
    /// against v12's claim, not v13's, so old versions are never deleted
    /// (SPEC §6.4).
    ///
    /// # Errors
    ///
    /// Returns [`Error::AppendOnlyViolation`](crate::Error::AppendOnlyViolation)
    /// if the ordinal or content hash already exists.
    pub fn put_persona(
        &self,
        dek: &Dek,
        model: &ghostr_core::persona::PersonaModel,
        nonce: [u8; 24],
    ) -> crate::Result<()> {
        let plaintext = encode_row(model)?;
        let aad = format!("persona:{}", model.version.ordinal);
        let sealed = seal_row(dek, &plaintext, &nonce, aad.as_bytes())?;

        self.conn
            .execute("UPDATE persona SET is_head = 0 WHERE is_head = 1", [])
            .map_err(|_| crate::Error::Backend {
                operation: "clear persona head",
            })?;
        self.conn
            .execute(
                "INSERT INTO persona
                 (ordinal, content_hash, parent_ordinal, created_at, is_head,
                  body_nonce, body_sealed)
                 VALUES (?1, ?2, ?3, ?4, 1, ?5, ?6)",
                params![
                    i64::from(model.version.ordinal),
                    model.version.content.to_hex(),
                    model.parent.map(|p| i64::from(p.ordinal)),
                    model.created_at.utc_millis(),
                    nonce.to_vec(),
                    sealed
                ],
            )
            .map_err(|e| match e {
                rusqlite::Error::SqliteFailure(f, _)
                    if f.code == rusqlite::ErrorCode::ConstraintViolation =>
                {
                    crate::Error::AppendOnlyViolation { table: "persona" }
                }
                _ => crate::Error::Backend {
                    operation: "insert persona",
                },
            })?;
        Ok(())
    }

    /// The current persona version, if one has been distilled.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Backend`](crate::Error::Backend) if the read fails.
    pub fn persona_head(
        &self,
        dek: &Dek,
    ) -> crate::Result<Option<ghostr_core::persona::PersonaModel>> {
        self.persona_row(
            dek,
            "SELECT ordinal, body_nonce, body_sealed FROM persona WHERE is_head = 1 LIMIT 1",
            None,
        )
    }

    /// One version by ordinal.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Backend`](crate::Error::Backend) if the read fails.
    pub fn get_persona(
        &self,
        dek: &Dek,
        ordinal: u32,
    ) -> crate::Result<Option<ghostr_core::persona::PersonaModel>> {
        self.persona_row(
            dek,
            "SELECT ordinal, body_nonce, body_sealed FROM persona WHERE ordinal = ?1",
            Some(i64::from(ordinal)),
        )
    }

    /// Reads one persona row.
    fn persona_row(
        &self,
        dek: &Dek,
        sql: &str,
        ordinal: Option<i64>,
    ) -> crate::Result<Option<ghostr_core::persona::PersonaModel>> {
        let read = |r: &rusqlite::Row<'_>| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, Vec<u8>>(1)?,
                r.get::<_, Vec<u8>>(2)?,
            ))
        };
        let row = match ordinal {
            Some(o) => self.conn.query_row(sql, [o], read).optional(),
            None => self.conn.query_row(sql, [], read).optional(),
        }
        .map_err(|_| crate::Error::Backend {
            operation: "read persona",
        })?;

        let Some((ordinal, nonce, sealed)) = row else {
            return Ok(None);
        };
        let nonce: [u8; 24] = nonce.try_into().map_err(|_| crate::Error::Backend {
            operation: "persona nonce length",
        })?;
        let aad = format!("persona:{ordinal}");
        let plaintext = open_row(dek, &sealed, &nonce, aad.as_bytes())
            .map_err(|_| crate::Error::RowDecryptFailed { table: "persona" })?;
        Ok(Some(decode_row(&plaintext, "persona")?))
    }

    /// Every version, newest first, without decrypting their facets.
    ///
    /// A history listing does not need the content, and not decrypting it is
    /// one fewer place for a persona to be in memory.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Backend`](crate::Error::Backend) if the read fails.
    pub fn persona_history(&self, limit: u32) -> crate::Result<Vec<PersonaSummary>> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT ordinal, content_hash, parent_ordinal, created_at, is_head
                 FROM persona ORDER BY ordinal DESC LIMIT ?1",
            )
            .map_err(|_| crate::Error::Backend {
                operation: "prepare persona history",
            })?;
        let rows = stmt
            .query_map([i64::from(limit)], |r| {
                Ok(PersonaSummary {
                    ordinal: r.get::<_, i64>(0)?.max(0).unsigned_abs() as u32,
                    content: r.get::<_, String>(1)?,
                    parent_ordinal: r
                        .get::<_, Option<i64>>(2)?
                        .map(|p| p.max(0).unsigned_abs() as u32),
                    created_at: Timestamp::new(r.get::<_, i64>(3)?, 0),
                    is_head: r.get::<_, i64>(4)? != 0,
                })
            })
            .map_err(|_| crate::Error::Backend {
                operation: "query persona history",
            })?;

        let mut out = Vec::new();
        for row in rows {
            out.push(row.map_err(|_| crate::Error::Backend {
                operation: "read persona history row",
            })?);
        }
        Ok(out)
    }
}

/// One persona version, without its facets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersonaSummary {
    /// Monotonic ordinal.
    pub ordinal: u32,
    /// Content hash, hex.
    pub content: String,
    /// The ordinal this was distilled from.
    pub parent_ordinal: Option<u32>,
    /// When it was distilled.
    pub created_at: Timestamp,
    /// Whether this is the current head.
    pub is_head: bool,
}

/// Quests.
impl SqliteStore {
    /// Stores a freshly issued quest.
    ///
    /// # Errors
    ///
    /// Returns [`Error::AppendOnlyViolation`](crate::Error::AppendOnlyViolation)
    /// if the id exists.
    pub fn put_quest(
        &self,
        dek: &Dek,
        quest: &ghostr_core::quest::Quest,
        nonce: [u8; 24],
    ) -> crate::Result<()> {
        let plaintext = encode_row(quest)?;
        let aad = format!("quest:{}", quest.id);
        let sealed = seal_row(dek, &plaintext, &nonce, aad.as_bytes())?;

        self.conn
            .execute(
                "INSERT INTO quest
                 (id, issued_for, issued_at, persona_ordinal, facet, kind_tag,
                  difficulty, confidence, answer_commitment, holdout, decoy,
                  expires_at, status, body_nonce, body_sealed)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
                params![
                    quest.id.to_string(),
                    quest.issued_for.to_string(),
                    quest.issued_at.utc_millis(),
                    i64::from(quest.persona_version.ordinal),
                    format!("{:?}", quest.facet),
                    quest.kind.variant_name(),
                    f64::from(quest.difficulty),
                    f64::from(quest.confidence),
                    quest.answer_commitment.to_hex(),
                    i64::from(quest.holdout),
                    i64::from(quest.decoy),
                    quest.expires_at.utc_millis(),
                    status_tag(quest.status),
                    nonce.to_vec(),
                    sealed
                ],
            )
            .map_err(|e| match e {
                rusqlite::Error::SqliteFailure(f, _)
                    if f.code == rusqlite::ErrorCode::ConstraintViolation =>
                {
                    crate::Error::AppendOnlyViolation { table: "quest" }
                }
                _ => crate::Error::Backend {
                    operation: "insert quest",
                },
            })?;
        Ok(())
    }

    /// Records a verdict against an open quest.
    ///
    /// Updates the sealed body and the answered columns. The commitment,
    /// holdout, and decoy columns are protected by a trigger — a commitment
    /// that could be rewritten after the answer would be worthless (I6).
    ///
    /// # Errors
    ///
    /// Returns [`Error::Backend`](crate::Error::Backend) if the write fails.
    pub fn answer_quest(
        &self,
        dek: &Dek,
        quest: &ghostr_core::quest::Quest,
        answered_at: Timestamp,
        answer_seconds: f32,
        nonce: [u8; 24],
    ) -> crate::Result<()> {
        let plaintext = encode_row(quest)?;
        let aad = format!("quest:{}", quest.id);
        let sealed = seal_row(dek, &plaintext, &nonce, aad.as_bytes())?;

        // `status = 'open'` in the WHERE clause is what makes a verdict
        // one-shot: a second answer matches no row rather than overwriting the
        // first. The intake checks this too, but a check in the caller is a
        // convention and a check here is a guarantee.
        let changed = self
            .conn
            .execute(
                "UPDATE quest
                 SET status = ?2, answered_at = ?3, answer_seconds = ?4,
                     body_nonce = ?5, body_sealed = ?6
                 WHERE id = ?1 AND status = 'open'",
                params![
                    quest.id.to_string(),
                    status_tag(quest.status),
                    answered_at.utc_millis(),
                    f64::from(answer_seconds),
                    nonce.to_vec(),
                    sealed
                ],
            )
            .map_err(|_| crate::Error::Backend {
                operation: "answer quest",
            })?;
        if changed == 0 {
            return Err(crate::Error::AppendOnlyViolation { table: "quest" });
        }
        Ok(())
    }

    /// One quest by id.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Backend`](crate::Error::Backend) if the read fails.
    pub fn get_quest(
        &self,
        dek: &Dek,
        id: ghostr_core::ids::QuestId,
    ) -> crate::Result<Option<ghostr_core::quest::Quest>> {
        let row = self
            .conn
            .query_row(
                "SELECT id, body_nonce, body_sealed FROM quest WHERE id = ?1",
                [id.to_string()],
                |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, Vec<u8>>(1)?,
                        r.get::<_, Vec<u8>>(2)?,
                    ))
                },
            )
            .optional()
            .map_err(|_| crate::Error::Backend {
                operation: "read quest",
            })?;
        row.map(|(id, nonce, sealed)| open_quest(dek, &id, nonce, &sealed))
            .transpose()
    }

    /// One quest by a full id or the short form `quest list` prints.
    ///
    /// The short form is the id's last eight hex digits, so the match is a
    /// suffix match. An ambiguous suffix is an error rather than a pick: the
    /// commands that take a quest id answer it, and answering the wrong one is
    /// unrecoverable.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Backend`](crate::Error::Backend) if the read fails or
    /// the needle matches more than one quest.
    pub fn find_quest(
        &self,
        dek: &Dek,
        needle: &str,
    ) -> crate::Result<Option<ghostr_core::quest::Quest>> {
        let suffix = needle.trim().trim_start_matches("qst:").to_lowercase();
        if suffix.is_empty() {
            return Ok(None);
        }
        let mut found = self.quest_query(
            dek,
            "SELECT id, body_nonce, body_sealed FROM quest
             WHERE id LIKE '%' || ?1 LIMIT 2",
            params![suffix],
        )?;
        if found.len() > 1 {
            return Err(crate::Error::Backend {
                operation: "resolve an ambiguous quest id",
            });
        }
        Ok(found.pop())
    }

    /// Quests matching a status, newest first.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Backend`](crate::Error::Backend) if the read fails.
    pub fn quests_with_status(
        &self,
        dek: &Dek,
        status: ghostr_core::quest::QuestStatus,
        limit: u32,
    ) -> crate::Result<Vec<ghostr_core::quest::Quest>> {
        self.quest_query(
            dek,
            "SELECT id, body_nonce, body_sealed FROM quest
             WHERE status = ?1 ORDER BY issued_at DESC LIMIT ?2",
            params![status_tag(status), i64::from(limit)],
        )
    }

    /// Answered, held-out, non-decoy quests — the only ones that may be scored.
    ///
    /// Filtered in SQL on the clear columns rather than after decryption. That
    /// is why `holdout` and `decoy` are not sealed: a scoring pass that had to
    /// decrypt every row to find the held-out ones would decrypt the whole
    /// corpus to compute a number (SPEC I7).
    ///
    /// # Errors
    ///
    /// Returns [`Error::Backend`](crate::Error::Backend) if the read fails.
    pub fn scoreable_quests(
        &self,
        dek: &Dek,
        since: Timestamp,
    ) -> crate::Result<Vec<(ghostr_core::quest::Quest, f32)>> {
        self.timed_quest_query(
            dek,
            "SELECT id, body_nonce, body_sealed, COALESCE(answer_seconds, 0.0)
             FROM quest
             WHERE holdout = 1 AND decoy = 0 AND status = 'answered'
               AND issued_at >= ?1
             ORDER BY issued_at",
            params![since.utc_millis()],
        )
    }

    /// Decoys and how long each took to answer, for the integrity signals.
    ///
    /// Answer times come back with them because the fast-verdict signal is
    /// computed over decoys and held-out quests together. A decoy reported with
    /// no time would read as instant, and would inflate the very signal the
    /// decoys exist to make legible.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Backend`](crate::Error::Backend) if the read fails.
    pub fn decoy_quests(
        &self,
        dek: &Dek,
        since: Timestamp,
    ) -> crate::Result<Vec<(ghostr_core::quest::Quest, f32)>> {
        self.timed_quest_query(
            dek,
            "SELECT id, body_nonce, body_sealed, COALESCE(answer_seconds, 0.0)
             FROM quest
             WHERE decoy = 1 AND issued_at >= ?1
             ORDER BY issued_at",
            params![since.utc_millis()],
        )
    }

    /// How many quests were issued for a day.
    ///
    /// Read from the clear `issued_for` column, so a caller can refuse to issue
    /// a day twice without opening a single sealed row.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Backend`](crate::Error::Backend) if the read fails.
    pub fn quests_issued_for(&self, date: NaiveDate) -> crate::Result<u32> {
        self.conn
            .query_row(
                "SELECT COUNT(*) FROM quest WHERE issued_for = ?1",
                [date.to_string()],
                |r| r.get::<_, i64>(0),
            )
            .map(|n| u32::try_from(n).unwrap_or(u32::MAX))
            .map_err(|_| crate::Error::Backend {
                operation: "count quests for a day",
            })
    }

    /// Marks every open quest past its expiry as expired.
    ///
    /// Returns how many were closed.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Backend`](crate::Error::Backend) if the write fails.
    pub fn expire_quests(&self, now: Timestamp) -> crate::Result<u64> {
        let changed = self
            .conn
            .execute(
                "UPDATE quest SET status = 'expired'
                 WHERE status = 'open' AND expires_at < ?1",
                [now.utc_millis()],
            )
            .map_err(|_| crate::Error::Backend {
                operation: "expire quests",
            })?;
        Ok(changed as u64)
    }

    /// Runs a quest query returning rows with their answer times.
    fn timed_quest_query(
        &self,
        dek: &Dek,
        sql: &str,
        params: impl rusqlite::Params,
    ) -> crate::Result<Vec<(ghostr_core::quest::Quest, f32)>> {
        let mut stmt = self.conn.prepare(sql).map_err(|_| crate::Error::Backend {
            operation: "prepare timed quest query",
        })?;
        let rows = stmt
            .query_map(params, |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, Vec<u8>>(1)?,
                    r.get::<_, Vec<u8>>(2)?,
                    r.get::<_, f64>(3)?,
                ))
            })
            .map_err(|_| crate::Error::Backend {
                operation: "run timed quest query",
            })?;

        let mut out = Vec::new();
        for row in rows {
            let (id, nonce, sealed, seconds) = row.map_err(|_| crate::Error::Backend {
                operation: "read timed quest row",
            })?;
            out.push((open_quest(dek, &id, nonce, &sealed)?, seconds as f32));
        }
        Ok(out)
    }

    /// Runs a quest query returning full rows.
    fn quest_query(
        &self,
        dek: &Dek,
        sql: &str,
        params: impl rusqlite::Params,
    ) -> crate::Result<Vec<ghostr_core::quest::Quest>> {
        let mut stmt = self.conn.prepare(sql).map_err(|_| crate::Error::Backend {
            operation: "prepare quest query",
        })?;
        let rows = stmt
            .query_map(params, |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, Vec<u8>>(1)?,
                    r.get::<_, Vec<u8>>(2)?,
                ))
            })
            .map_err(|_| crate::Error::Backend {
                operation: "run quest query",
            })?;

        let mut out = Vec::new();
        for row in rows {
            let (id, nonce, sealed) = row.map_err(|_| crate::Error::Backend {
                operation: "read quest row",
            })?;
            out.push(open_quest(dek, &id, nonce, &sealed)?);
        }
        Ok(out)
    }
}

/// Recent engagement with the quest loop.
///
/// Every field comes from clear columns — no row is decrypted to compute it.
/// A number that required reading the whole corpus would mean opening the
/// corpus to draw a progress bar.
#[derive(Debug, Clone, PartialEq)]
pub struct QuestEngagement {
    /// Quests issued in the window.
    pub issued: u32,
    /// Of those, how many were answered.
    pub answered: u32,
    /// Answer times in seconds, ascending.
    pub answer_seconds: Vec<f32>,
    /// Days with at least one answer, most recent first.
    pub answered_days: Vec<NaiveDate>,
}

/// The correction queue.
impl SqliteStore {
    /// Queues a correction against the persona.
    ///
    /// # Errors
    ///
    /// Returns [`Error::HoldoutLeak`](crate::Error::HoldoutLeak) if the delta
    /// came from a held-out quest (I7).
    pub fn queue_delta(
        &self,
        dek: &Dek,
        delta: &ghostr_core::persona::PersonaDelta,
        nonce: [u8; 24],
    ) -> crate::Result<()> {
        // I7, refused here rather than filtered at the far end. A held-out
        // correction reaching distillation invalidates every score since, and a
        // silent drop would hide the caller that produced it.
        if delta.from_holdout {
            return Err(crate::Error::HoldoutLeak);
        }

        let plaintext = encode_row(delta)?;
        // The row id is assigned by SQLite, so the AAD binds to the memory the
        // delta is about instead. Two deltas over one memory are legitimately
        // interchangeable; a delta moved onto a *different* memory is not, and
        // that is the swap this catches.
        let aad = format!("persona_delta:{}", delta.memory_id);
        let sealed = seal_row(dek, &plaintext, &nonce, aad.as_bytes())?;

        self.conn
            .execute(
                "INSERT INTO persona_delta
                 (facet, memory_id, queued_at, from_holdout, body_nonce, body_sealed)
                 VALUES (?1, ?2, ?3, 0, ?4, ?5)",
                params![
                    format!("{:?}", delta.facet),
                    delta.memory_id.to_string(),
                    delta.queued_at.utc_millis(),
                    nonce.to_vec(),
                    sealed
                ],
            )
            .map_err(|_| crate::Error::Backend {
                operation: "queue delta",
            })?;
        Ok(())
    }

    /// Reads the queued corrections without clearing them.
    ///
    /// A proposal the user never adopts must not consume the corrections it was
    /// built from — otherwise reviewing a diff and declining it would silently
    /// throw away the user's own words.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Backend`](crate::Error::Backend) if the read fails.
    pub fn peek_deltas(&self, dek: &Dek) -> crate::Result<Vec<ghostr_core::persona::PersonaDelta>> {
        self.read_deltas(dek, &self.conn)
    }

    /// Takes every queued correction, clearing the queue.
    ///
    /// Read and delete happen in one transaction. A delta applied twice would
    /// let one answer count twice, and a delta deleted without being applied
    /// would lose a correction the user took the trouble to write.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Backend`](crate::Error::Backend) if the read or the
    /// delete fails.
    pub fn drain_deltas(
        &self,
        dek: &Dek,
    ) -> crate::Result<Vec<ghostr_core::persona::PersonaDelta>> {
        let tx = self
            .conn
            .unchecked_transaction()
            .map_err(|_| crate::Error::Backend {
                operation: "begin drain",
            })?;

        let rows = self.read_deltas(dek, &tx)?;

        tx.execute("DELETE FROM persona_delta", [])
            .map_err(|_| crate::Error::Backend {
                operation: "clear delta queue",
            })?;
        tx.commit().map_err(|_| crate::Error::Backend {
            operation: "commit drain",
        })?;
        Ok(rows)
    }

    /// Reads the queue through whichever connection or transaction is given.
    fn read_deltas(
        &self,
        dek: &Dek,
        conn: &rusqlite::Connection,
    ) -> crate::Result<Vec<ghostr_core::persona::PersonaDelta>> {
        let mut stmt = conn
            .prepare(
                "SELECT memory_id, body_nonce, body_sealed
                 FROM persona_delta ORDER BY queued_at, id",
            )
            .map_err(|_| crate::Error::Backend {
                operation: "prepare delta read",
            })?;
        let mapped = stmt
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, Vec<u8>>(1)?,
                    r.get::<_, Vec<u8>>(2)?,
                ))
            })
            .map_err(|_| crate::Error::Backend {
                operation: "query deltas",
            })?;

        let mut out = Vec::new();
        for row in mapped {
            let (memory_id, nonce, sealed) = row.map_err(|_| crate::Error::Backend {
                operation: "read delta row",
            })?;
            let nonce: [u8; 24] = nonce.try_into().map_err(|_| crate::Error::Backend {
                operation: "delta nonce length",
            })?;
            let aad = format!("persona_delta:{memory_id}");
            let plaintext = open_row(dek, &sealed, &nonce, aad.as_bytes()).map_err(|_| {
                crate::Error::RowDecryptFailed {
                    table: "persona_delta",
                }
            })?;
            out.push(decode_row(&plaintext, "persona_delta")?);
        }
        Ok(out)
    }

    /// How many corrections are waiting.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Backend`](crate::Error::Backend) if the read fails.
    pub fn queued_delta_count(&self) -> crate::Result<u32> {
        self.conn
            .query_row("SELECT COUNT(*) FROM persona_delta", [], |r| {
                r.get::<_, i64>(0)
            })
            .map(|n| u32::try_from(n).unwrap_or(u32::MAX))
            .map_err(|_| crate::Error::Backend {
                operation: "count deltas",
            })
    }

    /// Engagement with the quest loop since `since`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Backend`](crate::Error::Backend) if the read fails.
    pub fn quest_engagement(&self, since: Timestamp) -> crate::Result<QuestEngagement> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT status, COALESCE(answer_seconds, 0.0), issued_for
                 FROM quest WHERE issued_at >= ?1",
            )
            .map_err(|_| crate::Error::Backend {
                operation: "prepare engagement",
            })?;
        let rows = stmt
            .query_map([since.utc_millis()], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, f64>(1)?,
                    r.get::<_, String>(2)?,
                ))
            })
            .map_err(|_| crate::Error::Backend {
                operation: "query engagement",
            })?;

        let mut issued = 0u32;
        let mut answer_seconds = Vec::new();
        let mut days = std::collections::BTreeSet::new();
        for row in rows {
            let (status, seconds, day) = row.map_err(|_| crate::Error::Backend {
                operation: "read engagement row",
            })?;
            issued = issued.saturating_add(1);
            if status == "answered" {
                answer_seconds.push(seconds as f32);
                if let Ok(date) = day.parse::<NaiveDate>() {
                    days.insert(date);
                }
            }
        }
        answer_seconds.sort_by(|a, b| a.partial_cmp(b).unwrap_or(core::cmp::Ordering::Equal));

        Ok(QuestEngagement {
            issued,
            answered: u32::try_from(answer_seconds.len()).unwrap_or(u32::MAX),
            answer_seconds,
            answered_days: days.into_iter().rev().collect(),
        })
    }
}

/// Decrypts one quest row.
fn open_quest(
    dek: &Dek,
    id: &str,
    nonce: Vec<u8>,
    sealed: &[u8],
) -> crate::Result<ghostr_core::quest::Quest> {
    let nonce: [u8; 24] = nonce.try_into().map_err(|_| crate::Error::Backend {
        operation: "quest nonce length",
    })?;
    let aad = format!("quest:{id}");
    let plaintext = open_row(dek, sealed, &nonce, aad.as_bytes())
        .map_err(|_| crate::Error::RowDecryptFailed { table: "quest" })?;
    decode_row(&plaintext, "quest")
}

/// The stored form of a quest status.
const fn status_tag(status: ghostr_core::quest::QuestStatus) -> &'static str {
    use ghostr_core::quest::QuestStatus;

    match status {
        QuestStatus::Open => "open",
        QuestStatus::Answered => "answered",
        QuestStatus::Expired => "expired",
        QuestStatus::Voided => "voided",
        // `QuestStatus` is `#[non_exhaustive]`; an unrecognised status must not
        // land in a column a scoring query filters on, so it stores as a value
        // no query selects.
        _ => "unknown",
    }
}

#[cfg(test)]
mod vector_tests {
    use ghostr_core::ids::VectorId;
    use ghostr_crypto::kdf::derive_dek;

    use super::tests_support::{dek, memory, store};
    use super::*;
    use crate::vector::{VectorFilter, VectorIndex as _};

    fn vector_id(n: u8) -> VectorId {
        VectorId::new(u64::from(n), [n; 10])
    }

    fn seeded(dir: &Path) -> (SqliteStore, Dek, Vec<MemoryId>) {
        let s = store(dir);
        let d = dek();
        let source = SourceId::new(1, [0u8; 10]);
        let mut ids = Vec::new();
        for (n, text) in [
            (1u8, "coffee with Nan"),
            (2, "fixed the parser"),
            (3, "long walk"),
        ] {
            let m = memory(source, n, text);
            ids.push(m.id);
            s.put_memory(&d, &m, [n; 24]).expect("put");
        }
        (s, d, ids)
    }

    #[test]
    fn a_vector_round_trips_and_finds_itself() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (s, d, ids) = seeded(dir.path());
        s.upsert(&d, ids[0], &[1.0, 0.0, 0.0], vector_id(1), [1u8; 24])
            .expect("upsert");
        let hits = s
            .knn(&d, &[1.0, 0.0, 0.0], 5, &VectorFilter::default())
            .expect("knn");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].memory, ids[0]);
        assert!((hits[0].similarity - 1.0).abs() < 1e-5);
    }

    /// I1. The index is the most reconstructible representation of the corpus,
    /// so it is the last thing that should be readable without the DEK.
    #[test]
    fn no_vector_component_appears_in_the_raw_database() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (s, d, ids) = seeded(dir.path());
        // A recognisable component that would survive as bytes if stored plain.
        let vector = [0.123_456_79_f32, 0.0, 0.0];
        s.upsert(&d, ids[0], &vector, vector_id(1), [1u8; 24])
            .expect("upsert");
        drop(s);

        let raw = std::fs::read(dir.path().join(DB_FILENAME)).expect("read db");
        let unit = crate::vector::normalize(&vector).expect("unit");
        let mut needle = Vec::new();
        for v in &unit {
            needle.extend_from_slice(&v.to_le_bytes());
        }
        assert!(
            !raw.windows(needle.len()).any(|w| w == needle),
            "the vector is on disk in the clear"
        );
    }

    #[test]
    fn ranking_is_by_similarity_and_deterministic() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (s, d, ids) = seeded(dir.path());
        s.upsert(&d, ids[0], &[1.0, 0.0, 0.0], vector_id(1), [1u8; 24])
            .expect("a");
        s.upsert(&d, ids[1], &[0.9, 0.1, 0.0], vector_id(2), [2u8; 24])
            .expect("b");
        s.upsert(&d, ids[2], &[0.0, 1.0, 0.0], vector_id(3), [3u8; 24])
            .expect("c");

        let hits = s
            .knn(&d, &[1.0, 0.0, 0.0], 3, &VectorFilter::default())
            .expect("knn");
        assert_eq!(hits[0].memory, ids[0]);
        assert_eq!(hits[1].memory, ids[1]);
        assert_eq!(hits[2].memory, ids[2]);

        let again = s
            .knn(&d, &[1.0, 0.0, 0.0], 3, &VectorFilter::default())
            .expect("knn");
        let order: Vec<_> = hits.iter().map(|h| h.memory).collect();
        let order_again: Vec<_> = again.iter().map(|h| h.memory).collect();
        assert_eq!(order, order_again);
    }

    /// SPEC Q18: a held-out memory must not come back through similarity
    /// search, or the holdout is not held out.
    #[test]
    fn an_excluded_memory_never_appears() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (s, d, ids) = seeded(dir.path());
        s.upsert(&d, ids[0], &[1.0, 0.0, 0.0], vector_id(1), [1u8; 24])
            .expect("a");
        s.upsert(&d, ids[1], &[0.9, 0.1, 0.0], vector_id(2), [2u8; 24])
            .expect("b");

        let filter = VectorFilter {
            exclude: vec![ids[0]],
            ..VectorFilter::default()
        };
        let hits = s.knn(&d, &[1.0, 0.0, 0.0], 5, &filter).expect("knn");
        assert!(hits.iter().all(|h| h.memory != ids[0]));
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn only_restricts_the_search_to_a_set() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (s, d, ids) = seeded(dir.path());
        s.upsert(&d, ids[0], &[1.0, 0.0, 0.0], vector_id(1), [1u8; 24])
            .expect("a");
        s.upsert(&d, ids[1], &[0.9, 0.1, 0.0], vector_id(2), [2u8; 24])
            .expect("b");

        let filter = VectorFilter {
            only: vec![ids[1]],
            ..VectorFilter::default()
        };
        let hits = s.knn(&d, &[1.0, 0.0, 0.0], 5, &filter).expect("knn");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].memory, ids[1]);
    }

    #[test]
    fn a_similarity_floor_drops_weak_matches() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (s, d, ids) = seeded(dir.path());
        s.upsert(&d, ids[0], &[1.0, 0.0, 0.0], vector_id(1), [1u8; 24])
            .expect("a");
        s.upsert(&d, ids[1], &[0.0, 1.0, 0.0], vector_id(2), [2u8; 24])
            .expect("b");

        let filter = VectorFilter {
            min_similarity: Some(0.5),
            ..VectorFilter::default()
        };
        let hits = s.knn(&d, &[1.0, 0.0, 0.0], 5, &filter).expect("knn");
        assert_eq!(hits.len(), 1);
    }

    /// Mixing two vector spaces produces neighbours that are not neighbours.
    /// It must be an error, not a coercion.
    #[test]
    fn a_width_change_is_refused_rather_than_coerced() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (s, d, ids) = seeded(dir.path());
        s.upsert(&d, ids[0], &[1.0, 0.0, 0.0], vector_id(1), [1u8; 24])
            .expect("a");
        let err = s
            .upsert(&d, ids[1], &[1.0, 0.0], vector_id(2), [2u8; 24])
            .expect_err("must refuse");
        assert!(matches!(
            err,
            crate::Error::VectorDimensionMismatch {
                found: 2,
                expected: 3
            }
        ));
        let err = s
            .knn(&d, &[1.0, 0.0], 5, &VectorFilter::default())
            .expect_err("must refuse");
        assert!(matches!(err, crate::Error::VectorDimensionMismatch { .. }));
    }

    /// The property that makes a rebuild survive a laptop lid closing.
    #[test]
    fn a_rebuild_keeps_vectors_already_at_the_new_width() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (s, d, ids) = seeded(dir.path());
        s.upsert(&d, ids[0], &[1.0, 0.0, 0.0], vector_id(1), [1u8; 24])
            .expect("a");

        let progress = s.rebuild("nomic-embed-text", 3).expect("rebuild");
        assert_eq!(progress.completed, 1);
        assert_eq!(progress.total, 3);
        assert_eq!(s.unembedded(10).expect("pending").len(), 2);
        assert!(!s.unembedded(10).expect("pending").contains(&ids[0]));
    }

    #[test]
    fn changing_the_model_width_drops_the_old_vectors() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (s, d, ids) = seeded(dir.path());
        s.upsert(&d, ids[0], &[1.0, 0.0, 0.0], vector_id(1), [1u8; 24])
            .expect("a");

        let progress = s.rebuild("another-model", 4).expect("rebuild");
        assert_eq!(progress.completed, 0, "the 3-wide vector is gone");
        assert_eq!(s.unembedded(10).expect("pending").len(), 3);
        assert_eq!(s.descriptor().expect("descriptor").model, "another-model");
    }

    /// A shredded memory whose embedding survived would make the shred a lie.
    #[test]
    fn removing_a_vector_takes_it_out_of_search() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (s, d, ids) = seeded(dir.path());
        s.upsert(&d, ids[0], &[1.0, 0.0, 0.0], vector_id(1), [1u8; 24])
            .expect("a");
        s.remove(ids[0]).expect("remove");
        assert!(
            s.knn(&d, &[1.0, 0.0, 0.0], 5, &VectorFilter::default())
                .expect("knn")
                .is_empty()
        );
    }

    #[test]
    fn upserting_the_same_memory_replaces_rather_than_duplicates() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (s, d, ids) = seeded(dir.path());
        s.upsert(&d, ids[0], &[1.0, 0.0, 0.0], vector_id(1), [1u8; 24])
            .expect("a");
        s.upsert(&d, ids[0], &[0.0, 1.0, 0.0], vector_id(2), [2u8; 24])
            .expect("again");
        assert_eq!(s.descriptor().expect("descriptor").count, 1);
        let hits = s
            .knn(&d, &[0.0, 1.0, 0.0], 5, &VectorFilter::default())
            .expect("knn");
        assert!((hits[0].similarity - 1.0).abs() < 1e-5);
    }

    #[test]
    fn an_empty_index_returns_nothing_rather_than_failing() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (s, d, _) = seeded(dir.path());
        assert!(
            s.knn(&d, &[1.0, 0.0, 0.0], 5, &VectorFilter::default())
                .expect("knn")
                .is_empty()
        );
    }

    /// The wrong key must fail loudly rather than returning noise that would be
    /// ranked as if it meant something.
    #[test]
    fn the_wrong_key_cannot_read_the_index() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (s, d, ids) = seeded(dir.path());
        s.upsert(&d, ids[0], &[1.0, 0.0, 0.0], vector_id(1), [1u8; 24])
            .expect("a");
        let wrong = derive_dek(&[7u8; 32]);
        let err = s
            .knn(&wrong, &[1.0, 0.0, 0.0], 5, &VectorFilter::default())
            .expect_err("must fail");
        assert!(matches!(err, crate::Error::RowDecryptFailed { .. }));
    }
}

#[cfg(test)]
mod source_tests {
    use ghostr_core::sensitivity::{Sensitivity, TrustLevel};

    use super::tests_support::{dek, store};
    use super::*;

    /// The bug schema v4 fixes: keying on `kind` alone collapsed two vaults at
    /// different paths into one source, and made a second `source add` of the
    /// same kind impossible.
    #[test]
    fn two_vaults_at_different_paths_are_two_sources() {
        let dir = tempfile::tempdir().expect("tempdir");
        let s = store(dir.path());
        let d = dek();
        let a = s
            .upsert_source(
                &d,
                SourceId::new(2, [2u8; 10]),
                "markdown_vault",
                "/notes/a",
                [2u8; 24],
            )
            .expect("a");
        let b = s
            .upsert_source(
                &d,
                SourceId::new(3, [3u8; 10]),
                "markdown_vault",
                "/notes/b",
                [3u8; 24],
            )
            .expect("b");
        assert_ne!(a, b);
        assert_eq!(
            s.all_sources(&d).expect("list").len(),
            3,
            "plus the fixture"
        );
    }

    /// And re-adding the same path is still a no-op, which is what makes
    /// `ingest` safe to run twice.
    #[test]
    fn re_adding_the_same_configuration_returns_the_existing_source() {
        let dir = tempfile::tempdir().expect("tempdir");
        let s = store(dir.path());
        let d = dek();
        let a = s
            .upsert_source(
                &d,
                SourceId::new(2, [2u8; 10]),
                "markdown_vault",
                "/notes",
                [2u8; 24],
            )
            .expect("a");
        let again = s
            .upsert_source(
                &d,
                SourceId::new(9, [9u8; 10]),
                "markdown_vault",
                "/notes",
                [9u8; 24],
            )
            .expect("again");
        assert_eq!(a, again);
    }

    /// A source's configuration names where the user keeps their notes, so it
    /// is content and is sealed like content (I1).
    #[test]
    fn a_source_path_is_not_readable_in_the_raw_database() {
        let dir = tempfile::tempdir().expect("tempdir");
        let s = store(dir.path());
        s.upsert_source(
            &dek(),
            SourceId::new(2, [2u8; 10]),
            "markdown_vault",
            "/home/someone/private-diary",
            [2u8; 24],
        )
        .expect("add");
        drop(s);
        let raw = std::fs::read(dir.path().join(DB_FILENAME)).expect("read");
        assert!(
            !raw.windows(13).any(|w| w == b"private-diary"),
            "the path is on disk in the clear"
        );
    }

    #[test]
    fn trust_and_sensitivity_round_trip() {
        let dir = tempfile::tempdir().expect("tempdir");
        let s = store(dir.path());
        let d = dek();
        let id = s
            .upsert_source_with(
                &d,
                &NewSourceRow {
                    id: SourceId::new(2, [2u8; 10]),
                    kind_tag: "structured_log",
                    config: "/health.jsonl",
                    trust: TrustLevel::SelfReported,
                    sensitivity: Sensitivity::Secret,
                },
                [2u8; 24],
            )
            .expect("add");
        let listed = s.all_sources(&d).expect("list");
        let found = listed.iter().find(|x| x.id == id).expect("present");
        assert_eq!(found.trust, TrustLevel::SelfReported);
        assert_eq!(found.default_sensitivity, Sensitivity::Secret);
        assert_eq!(found.config, "/health.jsonl");
    }

    /// A row written by a newer build reads as the strictest trust level, so an
    /// unknown value is treated as hostile input rather than as the user's own
    /// voice (THREAT_MODEL §T7).
    #[test]
    fn an_unrecognised_trust_level_reads_as_third_party() {
        assert_eq!(trust_from_str("something_new"), TrustLevel::ThirdParty);
        assert_eq!(trust_from_str("first_party"), TrustLevel::FirstParty);
    }

    #[test]
    fn a_cursor_round_trips() {
        let dir = tempfile::tempdir().expect("tempdir");
        let s = store(dir.path());
        let d = dek();
        let id = s
            .upsert_source(
                &d,
                SourceId::new(2, [2u8; 10]),
                "structured_log",
                "/h.jsonl",
                [2u8; 24],
            )
            .expect("add");
        s.set_source_cursor(id, r#"{"type":"timestamp","0":123}"#)
            .expect("set");
        let listed = s.all_sources(&d).expect("list");
        let found = listed.iter().find(|x| x.id == id).expect("present");
        assert!(found.cursor_json.contains("timestamp"));
    }
}

#[cfg(test)]
mod persona_tests {
    use ghostr_core::hash::{Tag, tagged_hash};
    use ghostr_core::ids::PersonaVersion;
    use ghostr_core::persona::{
        Facets, PersonaModel, PunctuationHabits, Register, SyntaxStats, VoiceProfile,
    };
    use ghostr_crypto::kdf::derive_dek;

    use super::tests_support::{dek, store};
    use super::*;

    fn model(ordinal: u32, marker: &str, parent: Option<PersonaVersion>) -> PersonaModel {
        PersonaModel {
            version: PersonaVersion {
                ordinal,
                content: tagged_hash(Tag::Persona, marker.as_bytes()),
            },
            parent,
            created_at: Timestamp::new(i64::from(ordinal) * 1_000, 0),
            facets: Facets {
                voice: VoiceProfile {
                    register: Register {
                        formality: 0.5,
                        warmth: 0.5,
                        hedging: 0.1,
                        profanity: 0.0,
                    },
                    lexicon: Vec::new(),
                    syntax: SyntaxStats {
                        mean_sentence_words: 12.0,
                        sentence_words_stddev: 3.0,
                        mean_clause_depth: 1.0,
                        fragment_rate: 0.1,
                    },
                    punctuation: PunctuationHabits {
                        em_dash_rate: 0.0,
                        lowercase_start_rate: 0.0,
                        emoji_rate: 0.0,
                        ellipsis_rate: 0.0,
                        unterminated_rate: 0.0,
                    },
                    exemplars: Vec::new(),
                },
                opinions: Vec::new(),
                relationships: Vec::new(),
                routines: Vec::new(),
                boundaries: Vec::new(),
                lore: Vec::new(),
            },
            derived_from: Vec::new(),
            diff: None,
        }
    }

    #[test]
    fn a_version_round_trips() {
        let dir = tempfile::tempdir().expect("tempdir");
        let s = store(dir.path());
        let d = dek();
        let m = model(1, "first", None);
        s.put_persona(&d, &m, [1u8; 24]).expect("put");

        let back = s.persona_head(&d).expect("head").expect("present");
        assert_eq!(back.version, m.version);
        assert_eq!(back.facets.voice.syntax.mean_sentence_words, 12.0);
    }

    /// A quest issued under v12 is scored against v12's claim, not v13's, so
    /// old versions are never deleted (SPEC §6.4).
    #[test]
    fn an_older_version_survives_a_new_head() {
        let dir = tempfile::tempdir().expect("tempdir");
        let s = store(dir.path());
        let d = dek();
        let first = model(1, "first", None);
        s.put_persona(&d, &first, [1u8; 24]).expect("v1");
        s.put_persona(&d, &model(2, "second", Some(first.version)), [2u8; 24])
            .expect("v2");

        assert_eq!(
            s.persona_head(&d)
                .expect("head")
                .expect("some")
                .version
                .ordinal,
            2
        );
        let old = s.get_persona(&d, 1).expect("read").expect("still there");
        assert_eq!(old.version, first.version);
    }

    /// A persona version is a claim the ghost has already answered quests
    /// under. Editing one would rewrite what it said after the fact.
    #[test]
    fn a_stored_version_cannot_be_edited_or_deleted() {
        let dir = tempfile::tempdir().expect("tempdir");
        let s = store(dir.path());
        s.put_persona(&dek(), &model(1, "first", None), [1u8; 24])
            .expect("put");

        assert!(
            s.conn
                .execute(
                    "UPDATE persona SET body_sealed = X'00' WHERE ordinal = 1",
                    []
                )
                .is_err()
        );
        assert!(
            s.conn
                .execute("DELETE FROM persona WHERE ordinal = 1", [])
                .is_err()
        );
    }

    #[test]
    fn a_duplicate_ordinal_is_refused() {
        let dir = tempfile::tempdir().expect("tempdir");
        let s = store(dir.path());
        let d = dek();
        s.put_persona(&d, &model(1, "first", None), [1u8; 24])
            .expect("put");
        let err = s
            .put_persona(&d, &model(1, "different", None), [2u8; 24])
            .expect_err("must refuse");
        assert!(matches!(
            err,
            crate::Error::AppendOnlyViolation { table: "persona" }
        ));
    }

    /// I1. A persona is the most concentrated description of a person in the
    /// vault, so it is sealed like any other content.
    #[test]
    fn no_facet_content_appears_in_the_raw_database() {
        let dir = tempfile::tempdir().expect("tempdir");
        let s = store(dir.path());
        let mut m = model(1, "first", None);
        m.facets.lore.push(ghostr_core::persona::LoreFact {
            statement: "the user lives in a lighthouse in Aberdeen".to_owned(),
            confidence: 0.9,
            evidence: vec![MemoryId::new(1, [1u8; 10])],
        });
        s.put_persona(&dek(), &m, [1u8; 24]).expect("put");
        drop(s);

        let raw = std::fs::read(dir.path().join(DB_FILENAME)).expect("read");
        for fragment in [b"lighthouse".as_slice(), b"Aberdeen".as_slice()] {
            assert!(
                !raw.windows(fragment.len()).any(|w| w == fragment),
                "a lore fact is on disk in the clear"
            );
        }
    }

    #[test]
    fn history_lists_newest_first_and_marks_the_head() {
        let dir = tempfile::tempdir().expect("tempdir");
        let s = store(dir.path());
        let d = dek();
        let first = model(1, "first", None);
        s.put_persona(&d, &first, [1u8; 24]).expect("v1");
        s.put_persona(&d, &model(2, "second", Some(first.version)), [2u8; 24])
            .expect("v2");

        let history = s.persona_history(10).expect("history");
        assert_eq!(history.len(), 2);
        assert_eq!(history[0].ordinal, 2);
        assert!(history[0].is_head);
        assert!(!history[1].is_head);
        assert_eq!(history[1].parent_ordinal, None);
        assert_eq!(history[0].parent_ordinal, Some(1));
    }

    #[test]
    fn the_wrong_key_cannot_read_a_version() {
        let dir = tempfile::tempdir().expect("tempdir");
        let s = store(dir.path());
        s.put_persona(&dek(), &model(1, "first", None), [1u8; 24])
            .expect("put");
        let wrong = derive_dek(&[7u8; 32]);
        assert!(matches!(
            s.persona_head(&wrong),
            Err(crate::Error::RowDecryptFailed { .. })
        ));
    }

    #[test]
    fn an_empty_vault_has_no_head() {
        let dir = tempfile::tempdir().expect("tempdir");
        let s = store(dir.path());
        assert!(s.persona_head(&dek()).expect("head").is_none());
    }
}

#[cfg(test)]
mod quest_tests {
    use ghostr_core::hash::{Tag, tagged_hash};
    use ghostr_core::ids::{PersonaVersion, QuestId};
    use ghostr_core::quest::{Facet, Quest, QuestKind, QuestStatus, Verdict};
    use ghostr_crypto::kdf::derive_dek;

    use super::tests_support::{dek, store};
    use super::*;

    const CLAIM: &str = "you spent the afternoon arguing with the timezone code again";

    fn quest(n: u8, holdout: bool, decoy: bool) -> Quest {
        Quest {
            id: QuestId::new(1_700_000_000_000 + u64::from(n), [n; 10]),
            issued_for: chrono::NaiveDate::from_ymd_opt(2026, 3, 1).expect("date"),
            issued_at: Timestamp::new(1_700_000_000_000 + i64::from(n), 0),
            persona_version: PersonaVersion {
                ordinal: 12,
                content: tagged_hash(Tag::Persona, b"v12"),
            },
            kind: QuestKind::FactRecall {
                claim: CLAIM.to_owned(),
                as_of: chrono::NaiveDate::from_ymd_opt(2026, 3, 1).expect("date"),
            },
            facet: Facet::Routine,
            difficulty: 0.4,
            evidence: Vec::new(),
            confidence: 0.7,
            answer_commitment: tagged_hash(Tag::QuestAnswer, &[n]),
            nonce: [n; 32],
            holdout,
            decoy,
            expires_at: Timestamp::new(1_700_000_100_000, 0),
            status: QuestStatus::Open,
            verdict: None,
        }
    }

    #[test]
    fn a_quest_round_trips() {
        let dir = tempfile::tempdir().expect("tempdir");
        let s = store(dir.path());
        let d = dek();
        let q = quest(1, true, false);
        s.put_quest(&d, &q, [1u8; 24]).expect("put");

        let back = s.get_quest(&d, q.id).expect("get").expect("present");
        assert_eq!(back.id, q.id);
        assert_eq!(back.answer_commitment, q.answer_commitment);
        assert_eq!(back.nonce, q.nonce);
        assert!(matches!(back.kind, QuestKind::FactRecall { .. }));
    }

    /// I1. The claim is the ghost's committed answer; if it were readable from
    /// the file, the pre-commitment would protect nothing.
    #[test]
    fn no_claim_text_appears_in_the_database_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        {
            let s = store(dir.path());
            s.put_quest(&dek(), &quest(1, true, false), [1u8; 24])
                .expect("put");
        }
        let raw = std::fs::read(dir.path().join(DB_FILENAME)).expect("read");
        assert!(
            !raw.windows(CLAIM.len()).any(|w| w == CLAIM.as_bytes()),
            "the claim survived into the database file in plaintext"
        );
    }

    #[test]
    fn the_wrong_key_cannot_read_a_quest() {
        let dir = tempfile::tempdir().expect("tempdir");
        let s = store(dir.path());
        let q = quest(1, true, false);
        s.put_quest(&dek(), &q, [1u8; 24]).expect("put");
        let wrong = derive_dek(&[7u8; 32]);
        assert!(matches!(
            s.get_quest(&wrong, q.id),
            Err(crate::Error::RowDecryptFailed { .. })
        ));
    }

    #[test]
    fn issuing_the_same_id_twice_is_refused() {
        let dir = tempfile::tempdir().expect("tempdir");
        let s = store(dir.path());
        let d = dek();
        let q = quest(1, true, false);
        s.put_quest(&d, &q, [1u8; 24]).expect("first");
        assert!(matches!(
            s.put_quest(&d, &q, [2u8; 24]),
            Err(crate::Error::AppendOnlyViolation { .. })
        ));
    }

    /// I6. A client that could rewrite the commitment after seeing the user's
    /// verdict could make the ghost right every time.
    #[test]
    fn a_commitment_cannot_be_rewritten() {
        let dir = tempfile::tempdir().expect("tempdir");
        let s = store(dir.path());
        let q = quest(1, true, false);
        s.put_quest(&dek(), &q, [1u8; 24]).expect("put");

        let err = s.conn.execute(
            "UPDATE quest SET answer_commitment = ?2 WHERE id = ?1",
            params![
                q.id.to_string(),
                tagged_hash(Tag::QuestAnswer, b"x").to_hex()
            ],
        );
        assert!(err.is_err(), "the trigger let the commitment be rewritten");
    }

    /// I7. Moving a quest out of the holdout after it was answered would let a
    /// bad day be reclassified as training data.
    #[test]
    fn the_holdout_flag_cannot_be_flipped_after_issue() {
        let dir = tempfile::tempdir().expect("tempdir");
        let s = store(dir.path());
        let q = quest(1, true, false);
        s.put_quest(&dek(), &q, [1u8; 24]).expect("put");

        assert!(
            s.conn
                .execute(
                    "UPDATE quest SET holdout = 0 WHERE id = ?1",
                    [q.id.to_string()],
                )
                .is_err()
        );
    }

    #[test]
    fn answering_moves_the_quest_out_of_the_open_list() {
        let dir = tempfile::tempdir().expect("tempdir");
        let s = store(dir.path());
        let d = dek();
        let q = quest(1, true, false);
        s.put_quest(&d, &q, [1u8; 24]).expect("put");
        assert_eq!(
            s.quests_with_status(&d, QuestStatus::Open, 10)
                .expect("open")
                .len(),
            1
        );

        let mut answered = q.clone();
        answered.status = QuestStatus::Answered;
        answered.verdict = Some(Verdict::Confirm);
        s.answer_quest(
            &d,
            &answered,
            Timestamp::new(1_700_000_050_000, 0),
            9.5,
            [2u8; 24],
        )
        .expect("answer");

        assert!(
            s.quests_with_status(&d, QuestStatus::Open, 10)
                .expect("open")
                .is_empty()
        );
        let back = s.get_quest(&d, q.id).expect("get").expect("present");
        assert_eq!(back.verdict, Some(Verdict::Confirm));
    }

    /// A verdict is one-shot. A second one would overwrite the first, which
    /// makes the score a function of how many times the user pressed the button.
    #[test]
    fn a_second_verdict_is_refused() {
        let dir = tempfile::tempdir().expect("tempdir");
        let s = store(dir.path());
        let d = dek();
        let q = quest(1, true, false);
        s.put_quest(&d, &q, [1u8; 24]).expect("put");

        let mut answered = q.clone();
        answered.status = QuestStatus::Answered;
        answered.verdict = Some(Verdict::Confirm);
        let at = Timestamp::new(1_700_000_050_000, 0);
        s.answer_quest(&d, &answered, at, 9.5, [2u8; 24])
            .expect("first");

        answered.verdict = Some(Verdict::Unknown);
        assert!(matches!(
            s.answer_quest(&d, &answered, at, 1.0, [3u8; 24]),
            Err(crate::Error::AppendOnlyViolation { .. })
        ));
        assert_eq!(
            s.get_quest(&d, q.id)
                .expect("get")
                .expect("present")
                .verdict,
            Some(Verdict::Confirm)
        );
    }

    #[test]
    fn answering_an_unknown_quest_is_refused() {
        let dir = tempfile::tempdir().expect("tempdir");
        let s = store(dir.path());
        let mut q = quest(9, true, false);
        q.status = QuestStatus::Answered;
        assert!(matches!(
            s.answer_quest(&dek(), &q, Timestamp::new(1, 0), 1.0, [1u8; 24]),
            Err(crate::Error::AppendOnlyViolation { .. })
        ));
    }

    /// I7. Anything but an answered, held-out, non-decoy quest is either
    /// training data or a trap, and scoring it makes the number a lie.
    #[test]
    fn only_answered_holdout_non_decoys_are_scoreable() {
        let dir = tempfile::tempdir().expect("tempdir");
        let s = store(dir.path());
        let d = dek();
        let at = Timestamp::new(1_700_000_050_000, 0);

        // Answered and held out: the one that counts.
        let good = quest(1, true, false);
        // Answered but trainable: excluded, it is the ghost's own study material.
        let trainable = quest(2, false, false);
        // Answered decoy: excluded, it is deliberately wrong.
        let decoy = quest(3, true, true);
        // Held out but never answered: excluded, there is no verdict to score.
        let unanswered = quest(4, true, false);

        for q in [&good, &trainable, &decoy, &unanswered] {
            s.put_quest(&d, q, [q.nonce[0]; 24]).expect("put");
        }
        for q in [&good, &trainable, &decoy] {
            let mut a = q.clone();
            a.status = QuestStatus::Answered;
            a.verdict = Some(Verdict::Confirm);
            s.answer_quest(&d, &a, at, 12.0, [q.nonce[0] + 100; 24])
                .expect("answer");
        }

        let scoreable = s
            .scoreable_quests(&d, Timestamp::new(0, 0))
            .expect("scoreable");
        assert_eq!(scoreable.len(), 1);
        assert_eq!(scoreable[0].0.id, good.id);
        assert!((scoreable[0].1 - 12.0).abs() < f32::EPSILON);
    }

    #[test]
    fn decoys_are_listed_for_the_rubber_stamp_signal() {
        let dir = tempfile::tempdir().expect("tempdir");
        let s = store(dir.path());
        let d = dek();
        s.put_quest(&d, &quest(1, true, false), [1u8; 24])
            .expect("plain");
        s.put_quest(&d, &quest(2, true, true), [2u8; 24])
            .expect("decoy");

        let decoys = s.decoy_quests(&d, Timestamp::new(0, 0)).expect("decoys");
        assert_eq!(decoys.len(), 1);
        assert!(decoys[0].0.decoy);
    }

    #[test]
    fn expiry_closes_only_open_quests_past_their_deadline() {
        let dir = tempfile::tempdir().expect("tempdir");
        let s = store(dir.path());
        let d = dek();
        let stale = quest(1, true, false);
        let mut fresh = quest(2, true, false);
        fresh.expires_at = Timestamp::new(1_800_000_000_000, 0);
        s.put_quest(&d, &stale, [1u8; 24]).expect("stale");
        s.put_quest(&d, &fresh, [2u8; 24]).expect("fresh");

        let closed = s
            .expire_quests(Timestamp::new(1_700_000_200_000, 0))
            .expect("expire");
        assert_eq!(closed, 1);
        assert_eq!(
            s.quests_with_status(&d, QuestStatus::Expired, 10)
                .expect("expired")
                .len(),
            1
        );
        // Idempotent: a second sweep finds nothing left to close.
        assert_eq!(
            s.expire_quests(Timestamp::new(1_700_000_200_000, 0))
                .expect("again"),
            0
        );
    }

    /// An expired quest is closed. Accepting a verdict afterwards would let a
    /// user answer a month of backlog in one sitting and call it fidelity.
    #[test]
    fn an_expired_quest_no_longer_accepts_a_verdict() {
        let dir = tempfile::tempdir().expect("tempdir");
        let s = store(dir.path());
        let d = dek();
        let q = quest(1, true, false);
        s.put_quest(&d, &q, [1u8; 24]).expect("put");
        s.expire_quests(Timestamp::new(1_700_000_200_000, 0))
            .expect("expire");

        let mut answered = q.clone();
        answered.status = QuestStatus::Answered;
        answered.verdict = Some(Verdict::Confirm);
        assert!(matches!(
            s.answer_quest(
                &d,
                &answered,
                Timestamp::new(1_700_000_300_000, 0),
                2.0,
                [2u8; 24]
            ),
            Err(crate::Error::AppendOnlyViolation { .. })
        ));
    }

    #[test]
    fn engagement_counts_without_decrypting_anything() {
        let dir = tempfile::tempdir().expect("tempdir");
        let s = store(dir.path());
        let d = dek();
        for n in 1..=3u8 {
            s.put_quest(&d, &quest(n, true, false), [n; 24])
                .expect("put");
        }
        let mut answered = quest(1, true, false);
        answered.status = QuestStatus::Answered;
        answered.verdict = Some(Verdict::Confirm);
        s.answer_quest(
            &d,
            &answered,
            Timestamp::new(1_700_000_050_000, 0),
            8.0,
            [9u8; 24],
        )
        .expect("answer");

        let e = s
            .quest_engagement(Timestamp::new(0, 0))
            .expect("engagement");
        assert_eq!(e.issued, 3);
        assert_eq!(e.answered, 1);
        assert_eq!(e.answer_seconds, vec![8.0]);
        assert_eq!(
            e.answered_days,
            vec![chrono::NaiveDate::from_ymd_opt(2026, 3, 1).expect("date")]
        );
    }

    #[test]
    fn scoreable_respects_the_window_start() {
        let dir = tempfile::tempdir().expect("tempdir");
        let s = store(dir.path());
        let d = dek();
        let q = quest(1, true, false);
        s.put_quest(&d, &q, [1u8; 24]).expect("put");
        let mut a = q.clone();
        a.status = QuestStatus::Answered;
        a.verdict = Some(Verdict::Confirm);
        s.answer_quest(&d, &a, Timestamp::new(1_700_000_050_000, 0), 5.0, [2u8; 24])
            .expect("answer");

        assert!(
            s.scoreable_quests(&d, Timestamp::new(1_800_000_000_000, 0))
                .expect("after")
                .is_empty()
        );
    }
}

#[cfg(test)]
mod delta_tests {
    use ghostr_core::ids::MemoryId;
    use ghostr_core::persona::PersonaDelta;
    use ghostr_core::quest::Facet;
    use ghostr_crypto::kdf::derive_dek;

    use super::tests_support::{dek, store};
    use super::*;

    fn delta(n: u8, from_holdout: bool) -> PersonaDelta {
        PersonaDelta {
            facet: Facet::Opinion,
            memory_id: MemoryId::new(u64::from(n), [n; 10]),
            correction_id: Some(MemoryId::new(100 + u64::from(n), [n; 10])),
            weight: 0.1,
            queued_at: Timestamp::new(1_700_000_000_000 + i64::from(n), 0),
            from_holdout,
        }
    }

    #[test]
    fn a_delta_round_trips_through_the_queue() {
        let dir = tempfile::tempdir().expect("tempdir");
        let s = store(dir.path());
        let d = dek();
        let queued = delta(1, false);
        s.queue_delta(&d, &queued, [1u8; 24]).expect("queue");

        let drained = s.drain_deltas(&d).expect("drain");
        assert_eq!(drained, vec![queued]);
    }

    /// I7. A held-out correction that reached distillation would mean the score
    /// is computed over data the model trained on.
    #[test]
    fn a_held_out_delta_is_refused() {
        let dir = tempfile::tempdir().expect("tempdir");
        let s = store(dir.path());
        assert!(matches!(
            s.queue_delta(&dek(), &delta(1, true), [1u8; 24]),
            Err(crate::Error::HoldoutLeak)
        ));
        assert_eq!(s.queued_delta_count().expect("count"), 0);
    }

    /// A delta applied twice would let one answer count twice.
    #[test]
    fn draining_empties_the_queue() {
        let dir = tempfile::tempdir().expect("tempdir");
        let s = store(dir.path());
        let d = dek();
        s.queue_delta(&d, &delta(1, false), [1u8; 24]).expect("a");
        s.queue_delta(&d, &delta(2, false), [2u8; 24]).expect("b");
        assert_eq!(s.queued_delta_count().expect("count"), 2);

        assert_eq!(s.drain_deltas(&d).expect("drain").len(), 2);
        assert_eq!(s.queued_delta_count().expect("count"), 0);
        assert!(s.drain_deltas(&d).expect("again").is_empty());
    }

    #[test]
    fn deltas_drain_in_the_order_they_were_queued() {
        let dir = tempfile::tempdir().expect("tempdir");
        let s = store(dir.path());
        let d = dek();
        s.queue_delta(&d, &delta(3, false), [3u8; 24]).expect("c");
        s.queue_delta(&d, &delta(1, false), [1u8; 24]).expect("a");

        let drained = s.drain_deltas(&d).expect("drain");
        assert_eq!(drained[0].memory_id, MemoryId::new(1, [1u8; 10]));
    }

    #[test]
    fn the_wrong_key_cannot_read_the_queue() {
        let dir = tempfile::tempdir().expect("tempdir");
        let s = store(dir.path());
        s.queue_delta(&dek(), &delta(1, false), [1u8; 24])
            .expect("queue");
        let wrong = derive_dek(&[7u8; 32]);
        assert!(matches!(
            s.drain_deltas(&wrong),
            Err(crate::Error::RowDecryptFailed { .. })
        ));
    }

    /// A failed drain must not eat the queue: the corrections are the user's own
    /// words and there is nowhere else to recover them from.
    #[test]
    fn a_failed_drain_leaves_the_queue_intact() {
        let dir = tempfile::tempdir().expect("tempdir");
        let s = store(dir.path());
        let d = dek();
        s.queue_delta(&d, &delta(1, false), [1u8; 24])
            .expect("queue");
        assert!(s.drain_deltas(&derive_dek(&[7u8; 32])).is_err());
        assert_eq!(s.queued_delta_count().expect("count"), 1);
        assert_eq!(s.drain_deltas(&d).expect("drain").len(), 1);
    }
}
