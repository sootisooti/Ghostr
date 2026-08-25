//! Relay transport.

use async_trait::async_trait;
use ghostr_core::identity::PublicKey;
use ghostr_crypto::event::SignedEvent;
use serde::{Deserialize, Serialize};

use crate::kinds::Kind;

/// Talks to relays.
#[async_trait]
pub trait RelayClient: Send + Sync {
    /// Publishes to every write relay.
    ///
    /// Succeeds if any relay accepts. Relays are individually unreliable and
    /// collectively fine, and treating a single rejection as failure would make
    /// publishing flaky for no gain.
    ///
    /// # Errors
    ///
    /// Returns [`Error::PublishRejected`](crate::Error::PublishRejected) if
    /// every relay refused, or
    /// [`Error::PublishingDisabled`](crate::Error::PublishingDisabled) if the
    /// scope is not enabled — the default state.
    async fn publish(
        &self,
        event: SignedEvent,
        scope: PublishScope,
    ) -> crate::Result<PublishReport>;

    /// Fetches events matching a filter.
    ///
    /// Implementations must verify signatures before returning. Relay-supplied
    /// events are untrusted input, and an unverified event that reaches the
    /// decoder is a forged manifest treated as real.
    ///
    /// # Errors
    ///
    /// Returns an error if every read relay is unreachable.
    async fn fetch(&self, filter: &Filter) -> crate::Result<Vec<SignedEvent>>;

    /// Opens a live subscription.
    ///
    /// # Errors
    ///
    /// Returns an error if no relay accepted the subscription.
    async fn subscribe(&self, filter: Filter) -> crate::Result<Box<dyn Subscription>>;
}

/// A live subscription.
#[async_trait]
pub trait Subscription: Send + Sync {
    /// The next event, or `None` when the subscription closes.
    ///
    /// # Errors
    ///
    /// Returns an error if the transport fails irrecoverably.
    async fn next(&mut self) -> crate::Result<Option<SignedEvent>>;

    /// Closes the subscription.
    async fn close(&mut self);
}

/// Which publishing permission a call is exercising.
///
/// Publishing is opt-in *per scope*, not globally. Enabling encrypted backup
/// must not silently enable the ghost to post, and a single boolean would make
/// exactly that mistake.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum PublishScope {
    /// Encrypted footage, persona, and quest backup.
    Backup,
    /// The ghost manifest.
    Manifest,
    /// Anchor receipts. Local-only by default (SPEC Q5).
    AnchorReceipts,
    /// Fidelity attestations.
    Fidelity,
    /// Ghost-authored notes.
    GhostNotes,
    /// Revocations.
    ///
    /// Always permitted. A revocation the user cannot publish because they
    /// disabled publishing is a revocation that does not happen.
    Revocation,
}

/// A relay query.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Filter {
    /// Restrict to these authors.
    pub authors: Vec<PublicKey>,
    /// Restrict to these Ghostr kinds.
    pub kinds: Vec<Kind>,
    /// Restrict to these raw kinds, for standard nostr kinds.
    pub raw_kinds: Vec<u16>,
    /// Restrict to these `d` tags.
    pub d_tags: Vec<String>,
    /// Only events at or after this Unix second.
    pub since: Option<u64>,
    /// Only events before this Unix second.
    pub until: Option<u64>,
    /// Maximum events.
    pub limit: Option<u32>,
}

/// What a publish achieved.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublishReport {
    /// Relays that accepted.
    pub accepted: Vec<String>,
    /// Relays that refused, with their reasons.
    pub rejected: Vec<(String, String)>,
    /// Relays that could not be reached.
    pub unreachable: Vec<String>,
}
