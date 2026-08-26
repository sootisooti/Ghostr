//! Encrypted local persistence.
//!
//! Every row carrying memory content is stored as
//! `XChaCha20-Poly1305(nonce, DEK, plaintext, aad = row_type || row_id)`. The
//! AAD binds ciphertext to its row, so a row moved inside the database fails to
//! decrypt rather than silently returning another record's content
//! (SPEC §10.2).
//!
//! # What is deliberately not encrypted
//!
//! Indexed metadata — timestamps, source ids, entity ids, sequence numbers, and
//! ciphertext lengths — is stored in the clear, because it has to be queryable.
//! An attacker holding the database file but not the DEK therefore learns the
//! *shape* of the corpus: how much, how often, how many distinct people, when
//! the user was active, when they stopped. That is a real and unfixed leak, and
//! it is documented rather than solved (THREAT_MODEL §T1).
//!
//! # Why traits first
//!
//! The trait surface exists so `ghostr-testkit` can supply an in-memory store
//! and the domain crates can be tested without a database. `rusqlite` and the
//! SQL arrive with M0's implementation; there is no ORM, because the schema
//! encodes invariants — a unique `seq`, append-only triggers — that an ORM
//! would obscure.
//!
//! # Status
//!
//! Implemented: memories, footage, sources, entities, the egress log, the
//! encrypted vector index, persona versions, and quests.

#![forbid(unsafe_code)]
// CLAUDE.md §5 denies unwrap/expect/panic in library code, and names tests as
// the exception: a failed assertion should panic loudly with a message, and
// threading `Result` through test bodies buries what is actually being asserted.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]
pub mod blob;
pub mod entity;
pub mod error;
pub mod footage;
pub mod memory;
pub mod persona;
pub mod quest;
pub mod schema;
pub mod sqlite;
pub mod vector;

pub use blob::BlobStore;
pub use entity::EntityStore;
pub use error::{Error, Result};
pub use footage::FootageStore;
pub use memory::MemoryStore;
pub use persona::PersonaStore;
pub use quest::QuestStore;
pub use sqlite::{DB_FILENAME, SqliteStore};
pub use vector::VectorIndex;
