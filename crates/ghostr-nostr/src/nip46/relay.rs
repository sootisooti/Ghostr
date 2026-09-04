//! Carrying NIP-46 over relays.
//!
//! [`Nip46Signer`](super::Nip46Signer) holds the protocol and every guard; this
//! is the pipe it speaks through. A request becomes a kind-24133 event, NIP-44
//! encrypted to the signer and addressed to it with a `p` tag; the reply comes
//! back the same way, addressed to us.
//!
//! # The client keypair is not the user's key
//!
//! NIP-46 has two keys on our side of the conversation: the **user's**, which
//! lives in the signer and is the whole point, and a **local keypair** that
//! signs and encrypts the 24133 envelopes. This transport takes a [`Signer`]
//! and a [`KeyRef`] for that local half, so the composition root decides which
//! key it is rather than this module choosing one silently.
//!
//! That choice has a privacy consequence and is not yet settled — see
//! **SPEC §14 Q22**. Whatever key is used becomes visible to the relay as "the
//! thing talking to this bunker", so it should be a key that does nothing else.

use async_trait::async_trait;
use ghostr_core::identity::{KeyRef, PublicKey};
use ghostr_core::time::{Clock, Rng};
use ghostr_crypto::Signer;
use ghostr_crypto::event::{SignedEvent, UnsignedEvent};

use crate::client::{Filter, PublishScope, RelayClient};

/// The NIP-46 event kind.
const NIP46_KIND: u16 = 24133;

/// How many times to look for the reply before giving up.
///
/// Each pass is one `fetch`, which returns what the relay has stored. A signer
/// on a phone may be waiting for a human to press a button, so this has to
/// outlast someone noticing a notification — but not indefinitely, or a signer
/// that will never answer holds the caller for ever.
const REPLY_ATTEMPTS: usize = 30;

/// A NIP-46 transport over relays.
pub struct RelayNip46Transport<C: RelayClient, S: Signer> {
    relays: C,
    /// Signs and encrypts the 24133 envelopes. Not the user's key.
    client_signer: S,
    client_key: KeyRef,
    client_pubkey: PublicKey,
    signer_pubkey: PublicKey,
    clock: Box<dyn Clock>,
    rng: Box<dyn Rng>,
}

impl<C: RelayClient, S: Signer> core::fmt::Debug for RelayNip46Transport<C, S> {
    /// Both keys are public, but printed short: a full pubkey in a log is a
    /// correlation handle for whoever reads the log.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RelayNip46Transport")
            .field("client", &self.client_pubkey.short())
            .field("signer", &self.signer_pubkey.short())
            .finish_non_exhaustive()
    }
}

impl<C: RelayClient, S: Signer> RelayNip46Transport<C, S> {
    /// Builds a transport to one signer.
    ///
    /// # Errors
    ///
    /// Returns an error if `client_key` is not a key `client_signer` holds.
    pub fn new(
        relays: C,
        client_signer: S,
        client_key: KeyRef,
        signer_pubkey: PublicKey,
        clock: Box<dyn Clock>,
        rng: Box<dyn Rng>,
    ) -> crate::Result<Self> {
        let client_pubkey = client_signer.public_key(client_key)?;
        Ok(Self {
            relays,
            client_signer,
            client_key,
            client_pubkey,
            signer_pubkey,
            clock,
            rng,
        })
    }

    /// The pubkey a relay sees as the client half of this conversation.
    #[must_use]
    pub const fn client_pubkey(&self) -> &PublicKey {
        &self.client_pubkey
    }

    /// Wraps one request in a signed, encrypted 24133 event.
    async fn envelope(&self, request: &str) -> crate::Result<SignedEvent> {
        let nonce = self.rng.salt();
        let content = self
            .client_signer
            .nip44_encrypt(
                self.client_key,
                &self.signer_pubkey,
                request.as_bytes(),
                nonce,
            )
            .await?;

        let event = UnsignedEvent {
            pubkey: self.client_pubkey,
            created_at: self.clock.now().utc_millis().unsigned_abs() / 1000,
            kind: NIP46_KIND,
            tags: vec![vec!["p".to_owned(), self.signer_pubkey.to_hex()]],
            content,
        };
        let sig = self
            .client_signer
            .sign_event(self.client_key, &event)
            .await?;
        Ok(SignedEvent {
            id: event.id(),
            event,
            sig,
        })
    }
}

#[async_trait]
impl<C: RelayClient, S: Signer> super::Nip46Transport for RelayNip46Transport<C, S> {
    async fn round_trip(&self, request: &str) -> crate::Result<String> {
        let envelope = self.envelope(request).await?;
        let sent_at = envelope.event.created_at;
        self.relays
            .publish(envelope, PublishScope::RemoteSigner)
            .await?;

        // Only events from this signer, addressed to this client, and no older
        // than the request. `authors` is the load-bearing field: without it any
        // relay user could publish a 24133 event tagged at us and have their
        // "reply" decrypted and parsed as the signer's.
        let filter = Filter {
            authors: vec![self.signer_pubkey],
            raw_kinds: vec![NIP46_KIND],
            p_tags: vec![self.client_pubkey],
            since: Some(sent_at),
            ..Filter::default()
        };

        for _ in 0..REPLY_ATTEMPTS {
            // The relay client verifies signatures before events reach here, so
            // an event claiming to be from the signer really is from it.
            for event in self.relays.fetch(&filter).await? {
                // Checked again rather than trusted to the filter: `authors` is
                // a request to the relay, and a relay is free to ignore it.
                if event.event.pubkey != self.signer_pubkey {
                    continue;
                }
                let Ok(plaintext) = self
                    .client_signer
                    .nip44_decrypt(self.client_key, &self.signer_pubkey, &event.event.content)
                    .await
                else {
                    // Not ours to read. Skipped rather than failed: a signer may
                    // serve other clients from the same key.
                    continue;
                };
                if let Ok(text) = String::from_utf8(plaintext) {
                    // Which reply answers which request is the protocol's
                    // problem, and `Nip46Signer` settles it by comparing ids.
                    // Returning the first decryptable reply would be wrong if it
                    // were the last word — it is not.
                    return Ok(text);
                }
            }
        }

        Err(crate::Error::Crypto(ghostr_crypto::Error::RemoteSigner {
            reason: "signer did not reply",
        }))
    }
}
