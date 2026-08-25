//! [`Memory`] — the atomic unit of the corpus.
//!
//! Everything ingested from every source normalises to this type. Memories are
//! **append-only** (SPEC I2): a correction writes a new `Memory` carrying
//! [`Memory::supersedes`], which preserves the record of the user changing their
//! mind — itself persona-relevant data.

use serde::{Deserialize, Serialize};

use crate::ids::{EntityId, MemoryId, SourceId, VectorId};
use crate::sensitivity::Sensitivity;
use crate::time::Timestamp;

/// One atomic recorded thing.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct Memory {
    /// Stable identifier.
    pub id: MemoryId,
    /// Which source produced it.
    pub source_id: SourceId,
    /// When the thing happened. `None` when unknowable — a note with no date.
    pub occurred_at: Option<Timestamp>,
    /// When Ghostr first saw it. Always known.
    pub ingested_at: Timestamp,
    /// What kind of thing this is.
    pub kind: MemoryKind,
    /// The content.
    pub body: MemoryBody,
    /// People, places, and projects this memory refers to.
    pub entities: Vec<EntityRef>,
    /// How much this should shape the persona model, in `0.0..=1.0`.
    pub salience: f32,
    /// How exposed this content may be. Read at the egress boundary.
    pub sensitivity: Sensitivity,
    /// Where it came from, and what the raw bytes hashed to.
    pub provenance: Provenance,
    /// 32 CSPRNG bytes blinding this memory's commitment leaf.
    ///
    /// Without it a low-entropy memory — "saw Nan today" is perhaps 30 guessable
    /// bits — has a commitment anyone can confirm by guessing. The salt makes
    /// the leaf hiding as well as binding, and deleting it is what makes
    /// crypto-shredding work (SPEC §7.2, Q6).
    pub salt: [u8; 32],
    /// The memory this one corrects, if any. Reads resolve to the head.
    pub supersedes: Option<MemoryId>,
    /// Local embedding, if one has been computed. Never leaves the device.
    pub embedding: Option<VectorId>,
}

impl core::fmt::Debug for Memory {
    /// Prints identifiers and shape, never content (SPEC I8).
    ///
    /// A derived `Debug` here would put memory bodies into every error message
    /// and log line that ever formats a `Memory`, which is exactly the leak the
    /// invariant exists to prevent.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Memory")
            .field("id", &self.id)
            .field("source_id", &self.source_id)
            .field("kind", &self.kind)
            .field("sensitivity", &self.sensitivity)
            .field("entities", &self.entities.len())
            .field("body", &self.body)
            .finish_non_exhaustive()
    }
}

/// What kind of thing a memory records.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum MemoryKind {
    /// Something the user said or wrote. The voice corpus.
    Utterance,
    /// Something the user noticed.
    Observation,
    /// Something that happened, with a time.
    Event,
    /// A durable claim about the world or the user.
    Fact,
    /// A claim about a person and the user's tie to them.
    Relationship,
    /// A recurring pattern.
    Habit,
    /// A place, at a time.
    Location,
    /// A file, link, or media reference, stored as a content-addressed blob.
    Artifact,
}

/// The content of a memory.
///
/// Text plus an optional structured payload: a habit log or a location fix has
/// fields worth keeping typed, while a journal entry is just prose.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct MemoryBody {
    /// The text.
    pub text: String,
    /// Source-specific structured data, if the adapter produced any.
    pub structured: Option<StructuredPayload>,
    /// Spans removed before storage, e.g. a detected secret.
    pub redactions: Vec<Span>,
}

impl core::fmt::Debug for MemoryBody {
    /// Prints lengths only (SPEC I8).
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MemoryBody")
            .field("text_len", &self.text.len())
            .field("structured", &self.structured)
            .field("redactions", &self.redactions.len())
            .finish()
    }
}

/// A source-specific structured payload, held as canonical CBOR.
///
/// Deliberately not `serde_json::Value`. Structured payloads are hashed into the
/// memory leaf along with everything else, and only canonical CBOR has a single
/// byte representation per value — a JSON value would let one payload produce
/// two commitments depending on map ordering. Keeping the bytes canonical from
/// the moment an adapter produces them also keeps a JSON dependency out of this
/// crate.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct StructuredPayload(Vec<u8>);

impl StructuredPayload {
    /// Wraps bytes that are already canonical CBOR.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Canonical`](crate::Error::Canonical) if the bytes are
    /// not canonical, so a non-canonical payload cannot enter the corpus and be
    /// discovered later at seal time.
    pub fn new(cbor: Vec<u8>) -> crate::Result<Self> {
        crate::canonical::verify_canonical(&cbor)?;
        Ok(Self(cbor))
    }

    /// The raw canonical CBOR.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Decodes the payload into a typed value.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Canonical`](crate::Error::Canonical) if the payload does
    /// not decode into `T`.
    pub fn decode<T: serde::de::DeserializeOwned>(&self) -> crate::Result<T> {
        crate::canonical::from_canonical_cbor(&self.0)
    }
}

impl core::fmt::Debug for StructuredPayload {
    /// Prints the byte length only (SPEC I8).
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "StructuredPayload({} bytes)", self.0.len())
    }
}

/// A half-open byte range within a [`MemoryBody::text`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Span {
    /// Start byte offset, inclusive.
    pub start: u32,
    /// End byte offset, exclusive.
    pub end: u32,
}

/// A reference from a memory to an entity.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EntityRef {
    /// The entity. The real name lives in the encrypted entity table.
    pub id: EntityId,
    /// Where the entity was named in the text, if it was named at all.
    pub span: Option<Span>,
    /// How confident resolution was, in `0.0..=1.0`.
    pub confidence: f32,
}

/// Where a memory came from.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Provenance {
    /// The source.
    pub source_id: SourceId,
    /// The source's own identifier: a nostr event id, an RSS guid, a file path.
    pub external_id: Option<String>,
    /// A URL, when one exists.
    pub url: Option<String>,
    /// Digest of the raw bytes as ingested, before normalisation.
    ///
    /// Lets a re-ingest detect that an upstream record changed under us, which
    /// is a fact worth recording rather than silently absorbing.
    pub raw_hash: crate::hash::Hash32,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::{Tag, tagged_hash};
    use crate::sensitivity::Sensitivity;
    use crate::time::Timestamp;

    fn memory(text: &str) -> Memory {
        let source = SourceId::new(1, [0u8; 10]);
        Memory {
            id: MemoryId::new(1, [1u8; 10]),
            source_id: source,
            occurred_at: Some(Timestamp::new(0, 0)),
            ingested_at: Timestamp::new(0, 0),
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
                external_id: None,
                url: None,
                raw_hash: tagged_hash(Tag::MemoryLeaf, b""),
            },
            salt: [0u8; 32],
            supersedes: None,
            embedding: None,
        }
    }

    /// I8. The reason `Debug` is hand-written here rather than derived.
    #[test]
    fn debug_never_prints_the_body() {
        let secret = "the passphrase is hunter2 and I met Nan at the clinic";
        let rendered = format!("{:?}", memory(secret));
        assert!(!rendered.contains("hunter2"));
        assert!(!rendered.contains("Nan"));
        assert!(rendered.contains("text_len"));
    }

    /// Provenance and identifiers are exactly what a log line needs.
    #[test]
    fn debug_prints_the_identifiers_it_promises() {
        let rendered = format!("{:?}", memory("anything"));
        assert!(rendered.contains("Utterance"));
        assert!(rendered.contains("Private"));
        assert!(rendered.contains("entities"));
    }

    #[test]
    fn a_structured_payload_round_trips_through_canonical_cbor() {
        #[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug)]
        struct Place {
            name: String,
            visits: u32,
        }
        let value = Place {
            name: "clinic".to_owned(),
            visits: 2,
        };
        let bytes = crate::canonical::to_canonical_cbor(&value).unwrap();
        let payload = StructuredPayload::new(bytes).unwrap();
        assert_eq!(payload.decode::<Place>().unwrap(), value);
    }

    /// Non-canonical bytes are refused at the boundary, not at seal time.
    #[test]
    fn a_non_canonical_payload_is_refused() {
        // A map with keys out of canonical order.
        let bytes = vec![0xa2, 0x61, b'b', 0x01, 0x61, b'a', 0x02];
        assert!(StructuredPayload::new(bytes).is_err());
    }

    /// I8 again: the payload is content, so its `Debug` shows a length.
    #[test]
    fn a_structured_payload_debug_shows_only_a_length() {
        let bytes = crate::canonical::to_canonical_cbor(&"clinic").unwrap();
        let rendered = format!("{:?}", StructuredPayload::new(bytes).unwrap());
        assert!(!rendered.contains("clinic"));
        assert!(rendered.contains("bytes"));
    }
}
