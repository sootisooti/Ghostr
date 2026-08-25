//! The SQL schema, and what is deliberately left readable.
//!
//! # The encryption boundary
//!
//! Every column holding memory content, entity names, or footage prose is an
//! `XChaCha20-Poly1305` envelope keyed by the DEK, with the row's identity as
//! AAD. Nothing readable survives without the nostr secret key.
//!
//! Indexed metadata — ids, timestamps, sequence numbers, ciphertext lengths — is
//! stored in the clear because it has to be queryable. An attacker with the
//! database file and no key therefore learns the *shape* of the corpus: how
//! much, how often, how many distinct people, when the user was active, when
//! they stopped. That is a real and unfixed leak, documented rather than
//! solved (THREAT_MODEL §T1).
//!
//! # Invariants held by the schema, not by application code
//!
//! - `footage.seq` is `PRIMARY KEY`, so two devices cannot both seal a day. That
//!   is the fork guard (SPEC Q10).
//! - Triggers reject `UPDATE` and `DELETE` on `footage`, so a sealed day is
//!   immutable even to a bug in this crate (SPEC I2).
//! - `memory.id` is `PRIMARY KEY` and there is no `UPDATE` path; corrections
//!   insert a new row carrying `supersedes`.

/// Statements that create an empty store, in order.
pub const SCHEMA_V1: &str = r"
CREATE TABLE meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
) STRICT;

CREATE TABLE source (
    id                  TEXT PRIMARY KEY,
    kind                TEXT NOT NULL,
    trust               TEXT NOT NULL,
    default_sensitivity TEXT NOT NULL,
    enabled             INTEGER NOT NULL,
    cursor_json         TEXT NOT NULL,
    config_nonce        BLOB NOT NULL,
    config_sealed       BLOB NOT NULL
) STRICT;

-- Append-only. A correction is a new row pointing at the one it supersedes.
CREATE TABLE memory (
    id             TEXT PRIMARY KEY,
    source_id      TEXT NOT NULL REFERENCES source(id),
    occurred_at    INTEGER,
    occurred_off   INTEGER,
    ingested_at    INTEGER NOT NULL,
    ingested_off   INTEGER NOT NULL,
    kind           TEXT NOT NULL,
    sensitivity    TEXT NOT NULL,
    salience       INTEGER NOT NULL,
    supersedes     TEXT REFERENCES memory(id),
    -- Digest of the raw source bytes, used to skip records already ingested.
    raw_hash       TEXT NOT NULL,
    -- Blinding salt for this memory's commitment leaf. Destroyed on shred, which
    -- is what makes the leaf unopenable while the chain still verifies (Q6).
    salt           BLOB,
    body_nonce     BLOB,
    body_sealed    BLOB,
    shredded_at    INTEGER,
    shred_reason   TEXT
) STRICT;

CREATE INDEX memory_occurred_idx ON memory(occurred_at);
CREATE INDEX memory_ingested_idx ON memory(ingested_at);
CREATE UNIQUE INDEX memory_raw_hash_idx ON memory(source_id, raw_hash);

CREATE TABLE entity (
    id         TEXT PRIMARY KEY,
    kind       TEXT NOT NULL,
    pseudonym  TEXT NOT NULL,
    first_seen INTEGER NOT NULL,
    last_seen  INTEGER NOT NULL,
    -- The real name is the highest-value target in the store after the corpus
    -- itself, so it is sealed like memory content (THREAT_MODEL §T10).
    name_nonce BLOB NOT NULL,
    name_sealed BLOB NOT NULL,
    -- Keyed digest of the normalised name, so resolution can look an entity up
    -- without the plaintext and without a scan-and-decrypt over every row.
    name_tag   TEXT NOT NULL UNIQUE
) STRICT;

CREATE TABLE memory_entity (
    memory_id TEXT NOT NULL REFERENCES memory(id),
    entity_id TEXT NOT NULL REFERENCES entity(id),
    PRIMARY KEY (memory_id, entity_id)
) STRICT;

-- Sealed and immutable. `seq` is the primary key, which is the fork guard.
CREATE TABLE footage (
    seq          INTEGER PRIMARY KEY,
    date         TEXT NOT NULL UNIQUE,
    tz           TEXT NOT NULL,
    window_start INTEGER NOT NULL,
    window_end   INTEGER NOT NULL,
    empty        INTEGER NOT NULL,
    merkle_root  TEXT NOT NULL,
    prev_link    TEXT NOT NULL,
    link         TEXT NOT NULL,
    leaf_count   INTEGER NOT NULL,
    sealed_at    INTEGER NOT NULL,
    sealed_off   INTEGER NOT NULL,
    body_nonce   BLOB NOT NULL,
    body_sealed  BLOB NOT NULL
) STRICT;

-- SPEC I2/I3: a sealed footage is immutable and the chain is never rewritten.
-- Enforced here rather than in application code, because the application is
-- exactly what might be wrong.
CREATE TRIGGER footage_is_immutable
BEFORE UPDATE ON footage
BEGIN
    SELECT RAISE(ABORT, 'footage is sealed and cannot be modified');
END;

CREATE TRIGGER footage_is_permanent
BEFORE DELETE ON footage
BEGIN
    SELECT RAISE(ABORT, 'footage is sealed and cannot be deleted');
END;

CREATE TABLE footage_memory (
    seq       INTEGER NOT NULL REFERENCES footage(seq),
    memory_id TEXT NOT NULL REFERENCES memory(id),
    leaf      TEXT NOT NULL,
    PRIMARY KEY (seq, memory_id)
) STRICT;

CREATE TABLE anchor (
    seq          INTEGER PRIMARY KEY REFERENCES footage(seq),
    state        TEXT NOT NULL,
    digest       TEXT NOT NULL,
    submitted_at INTEGER,
    block_height INTEGER,
    attempts     INTEGER NOT NULL DEFAULT 0,
    detail       TEXT,
    ots          BLOB
) STRICT;
";

/// `meta` keys.
pub mod meta_key {
    /// Schema version, as a decimal string.
    pub const SCHEMA_VERSION: &str = "schema_version";
    /// The chain identifier this store holds.
    pub const CHAIN_ID: &str = "chain_id";
    /// The identity public key, hex.
    pub const IDENTITY_PUBKEY: &str = "identity_pubkey";
    /// The genesis link, hex.
    pub const GENESIS_LINK: &str = "genesis_link";
    /// The identity's home timezone.
    pub const HOME_TZ: &str = "home_tz";
    /// When the chain was created, as Unix milliseconds.
    pub const CREATED_AT: &str = "created_at";
}
