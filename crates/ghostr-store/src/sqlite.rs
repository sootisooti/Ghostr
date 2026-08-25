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
use ghostr_core::sensitivity::Sensitivity;
use ghostr_core::time::Timestamp;
use ghostr_crypto::kdf::{Dek, open_row, seal_row};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};

use crate::memory::{MemoryQuery, RedactionReason, TimeRange};
use crate::schema::{SCHEMA_V1, meta_key};

/// The database filename inside the data directory.
pub const DB_FILENAME: &str = "ghostr.db";

/// The schema version this build writes.
pub const SCHEMA_VERSION: u32 = 1;

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

        match existing.as_deref().map(str::parse::<u32>) {
            Some(Ok(v)) if v > SCHEMA_VERSION => {
                // Refuse rather than guess. A downgrade that writes with an older
                // understanding of the schema can corrupt a chain beyond repair.
                Err(crate::Error::SchemaTooNew {
                    found: v,
                    supported: SCHEMA_VERSION,
                })
            }
            Some(Ok(_)) => Ok(()),
            _ => {
                self.conn
                    .execute_batch(SCHEMA_V1)
                    .map_err(|_| crate::Error::Backend {
                        operation: "apply schema",
                    })?;
                self.set_meta(meta_key::SCHEMA_VERSION, &SCHEMA_VERSION.to_string())?;
                Ok(())
            }
        }
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
        if let Some(existing) = self
            .conn
            .query_row("SELECT id FROM source WHERE kind = ?1", [kind_tag], |r| {
                r.get::<_, String>(0)
            })
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
                  config_nonce, config_sealed)
                 VALUES (?1, ?2, 'first_party', 'private', 1, '{}', ?3, ?4)",
                params![id.to_string(), kind_tag, nonce.to_vec(), sealed],
            )
            .map_err(|_| crate::Error::Backend {
                operation: "insert source",
            })?;
        Ok(id)
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

/// Unused in M0; kept so the query type stays exercised by the compiler.
#[allow(dead_code)]
fn _assert_query_type(_q: &MemoryQuery) {}

#[cfg(test)]
mod tests {
    use ghostr_core::memory::MemoryBody;
    use ghostr_crypto::kdf::derive_dek;

    use super::*;

    const SECRET_TEXT: &str = "met Nan at the tea shop and finally fixed the timezone bug";

    fn dek() -> Dek {
        derive_dek(&[42u8; 32])
    }

    fn store(dir: &Path) -> SqliteStore {
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

    fn memory(source: SourceId, n: u8, text: &str) -> Memory {
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

        let needles = ["Nan", "tea shop", "timezone bug", SECRET_TEXT];
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
