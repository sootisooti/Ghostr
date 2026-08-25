//! Encoding Ghostr payloads into nostr events, and decoding them back.
//!
//! # Disclosure is enforced by construction (SPEC I10)
//!
//! [`GhostNoteBuilder`] is the only way to build a ghost-authored kind-1 event,
//! and it always emits the disclosure tags. There is no method to omit them and
//! no constructor that bypasses it, so "a ghost note without disclosure cannot
//! be constructed" is a property of the API rather than a rule contributors are
//! asked to remember.
//!
//! A ghost that can pass as its principal without a machine-readable marker is
//! an impersonation tool, which is a different product than this one.

use ghostr_core::identity::PublicKey;
use ghostr_crypto::event::UnsignedEvent;
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::kinds::Kind;

/// The tag marking an event as ghost-authored.
pub const DISCLOSURE_TAG: [&str; 3] = ["ghostr", "v1", "ghost-authored"];

/// The `client` tag value.
pub const CLIENT_TAG_VALUE: &str = "ghostr";

/// Encodes a payload into an unsigned event, encrypting if the kind requires it.
///
/// # Errors
///
/// Returns an error if serialization or encryption fails.
pub fn encode<T: Serialize>(
    kind: Kind,
    identifier: &str,
    author: &PublicKey,
    created_at: u64,
    payload: &T,
) -> crate::Result<UnsignedEvent> {
    todo!("serialize, encrypt when kind.is_encrypted(), attach the d tag")
}

/// Decodes an event into a payload.
///
/// The event's signature and id must already have been verified: relay-supplied
/// events are untrusted input, and decoding one that was not checked is how a
/// forged manifest gets treated as real.
///
/// # Errors
///
/// Returns [`Error::MalformedPayload`](crate::Error::MalformedPayload) if the
/// content does not decode as `T`.
pub fn decode<T: DeserializeOwned>(kind: Kind, event: &UnsignedEvent) -> crate::Result<T> {
    todo!("check the kind and d tag, decrypt when needed, deserialize")
}

/// Builds the NIP-78 (kind 30078) mirror of an event.
///
/// Published alongside the 3178x form so that correctness never depends on an
/// unclaimed kind block being ours (SPEC Q3).
///
/// # Errors
///
/// Returns an error if the source event cannot be re-encoded.
pub fn mirror_as_nip78(event: &UnsignedEvent) -> crate::Result<UnsignedEvent> {
    todo!("re-emit under kind 30078 with the same d tag and content")
}

/// Builds ghost-authored kind-1 notes, disclosure tags included.
///
/// Every constructed event carries `["ghostr","v1","ghost-authored"]`, a `p` tag
/// naming the principal, and `["client","ghostr"]`.
#[derive(Debug)]
pub struct GhostNoteBuilder {
    ghost_pubkey: PublicKey,
    principal: PublicKey,
    content: String,
}

impl GhostNoteBuilder {
    /// Starts a note.
    ///
    /// Requires the principal's pubkey up front, so a note that does not name
    /// who it is speaking for cannot be started, let alone finished.
    #[must_use]
    pub fn new(ghost_pubkey: PublicKey, principal: PublicKey) -> Self {
        Self {
            ghost_pubkey,
            principal,
            content: String::new(),
        }
    }

    /// Sets the note text.
    #[must_use]
    pub fn content(mut self, text: impl Into<String>) -> Self {
        self.content = text.into();
        self
    }

    /// Builds the event with its disclosure tags.
    ///
    /// # Errors
    ///
    /// Returns an error if the content is empty.
    pub fn build(self, created_at: u64) -> crate::Result<UnsignedEvent> {
        todo!("emit kind 1 with the disclosure, principal p, and client tags")
    }
}

/// Whether an event from a relay carries valid ghost disclosure tags.
///
/// For inbound events, where a third party may have published something claiming
/// to be a ghost without disclosing it. Outbound events cannot lack the tags.
#[must_use]
pub fn has_disclosure(event: &UnsignedEvent) -> bool {
    todo!("check for the ghostr disclosure tag and a principal p tag")
}
