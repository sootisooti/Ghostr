//! NIP-46: signing with a key this process does not hold.
//!
//! A *remote signer* — nsecBunker, nsec.app, Amber on a phone — holds the user's
//! key and answers requests about it. This module is the client half: it turns
//! [`Signer`] calls into NIP-46 requests and turns the answers back, so a vault
//! whose identity lives somewhere else looks identical to every call site.
//!
//! # Everything a signer says is untrusted
//!
//! The point of a remote signer is that it holds a key we cannot see. That is
//! also the reason it must not be believed: we ask for an operation and get back
//! bytes, with no way to re-derive them. Whoever runs the signer — or anyone who
//! has compromised it, or a relay in the middle replaying old traffic — chooses
//! what those bytes are.
//!
//! Three things are checked before an answer is used, and each is a test:
//!
//! 1. **The response id matches the request id.** Otherwise one reply can be
//!    read as the answer to a different question.
//! 2. **A returned signature is verified against the event we asked to be
//!    signed.** NIP-46's `sign_event` hands back a whole event, not a signature,
//!    so a signer can return a *different* event, correctly signed. Comparing
//!    ids catches it: the id is a hash of the body, so an id equal to ours means
//!    the body is ours.
//! 3. **The user pubkey is pinned at construction.** A signer that answers
//!    `get_public_key` with a different key later has switched identity, and
//!    every signature after that would be someone else's.
//!
//! # What this cannot do
//!
//! Supply the vault's DEK. It has no way to — and does not need to, because the
//! DEK comes from the vault seed (SPEC §14 Q21). That change is what makes this
//! module possible at all: with the DEK derived from the identity key, a vault
//! whose identity lives on a phone could not be decrypted by anything.

pub mod relay;

use core::sync::atomic::{AtomicU64, Ordering};

use async_trait::async_trait;
use ghostr_core::identity::{Account, KeyRef, PublicKey};
use ghostr_crypto::event::{Signature, SignedEvent, UnsignedEvent};
use ghostr_crypto::{Error as CryptoError, Signer};
use serde::{Deserialize, Serialize};

/// Carries one NIP-46 request to a signer and brings back its response.
///
/// Separated from the protocol so the request/response logic — which is where
/// every guard lives — is testable without a relay. The relay-backed
/// implementation wraps each request in a kind-24133 event, NIP-44 encrypted to
/// the signer, and waits for the reply addressed back to us.
#[async_trait]
pub trait Nip46Transport: Send + Sync {
    /// Sends one JSON request and returns the JSON response.
    ///
    /// # Errors
    ///
    /// Returns an error if the signer cannot be reached or does not answer.
    async fn round_trip(&self, request: &str) -> crate::Result<String>;
}

/// The NIP-46 methods this client uses.
///
/// A closed set. `nip04_encrypt`/`nip04_decrypt` are deliberately absent —
/// NIP-04 is superseded and its use here would mean encrypting a user's data
/// with a scheme this project does not otherwise implement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Method {
    Connect,
    GetPublicKey,
    SignEvent,
    Nip44Encrypt,
    Nip44Decrypt,
    Ping,
}

impl Method {
    /// The wire name, exactly as NIP-46 spells it.
    const fn as_str(self) -> &'static str {
        match self {
            Self::Connect => "connect",
            Self::GetPublicKey => "get_public_key",
            Self::SignEvent => "sign_event",
            Self::Nip44Encrypt => "nip44_encrypt",
            Self::Nip44Decrypt => "nip44_decrypt",
            Self::Ping => "ping",
        }
    }
}

/// A request to a remote signer.
#[derive(Debug, Clone, Serialize)]
struct Request {
    id: String,
    method: &'static str,
    params: Vec<String>,
}

/// A response from a remote signer.
///
/// Both `result` and `error` are optional because a signer may send either, and
/// a malformed signer may send neither — which is a failure, not a success with
/// an empty result.
#[derive(Debug, Clone, Deserialize)]
struct Response {
    id: String,
    #[serde(default)]
    result: Option<String>,
    #[serde(default)]
    error: Option<String>,
}

/// A [`Signer`] backed by a NIP-46 remote signer.
pub struct Nip46Signer<T: Nip46Transport> {
    transport: T,
    /// The user's public key, learned once and never re-asked.
    user_pubkey: PublicKey,
    /// Which account this signer answers for.
    ///
    /// A remote signer holds one key. Asked for another account it refuses,
    /// rather than signing with the only key it has — which would produce an
    /// event that verifies against the wrong person.
    account: Account,
    /// Request-id prefix, supplied by the caller.
    session: String,
    /// Monotonic counter completing each request id.
    ///
    /// A counter rather than fresh randomness per call: ids only have to
    /// correlate a reply with its request on a channel that is already
    /// encrypted to the signer, and entropy belongs in the composition root
    /// (ARCHITECTURE §4.7). The caller-supplied prefix is what keeps two
    /// sessions from colliding.
    next_id: AtomicU64,
}

impl<T: Nip46Transport> core::fmt::Debug for Nip46Signer<T> {
    /// Prints the account and nothing about the key beyond its short form.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Nip46Signer")
            .field("account", &self.account)
            .field("user", &self.user_pubkey.short())
            .finish_non_exhaustive()
    }
}

impl<T: Nip46Transport> Nip46Signer<T> {
    /// Connects to a signer and pins the key it says it holds.
    ///
    /// Performs the NIP-46 handshake: `connect`, then `get_public_key`, which
    /// the NIP requires because the signer's own pubkey and the user's are
    /// different keys. The result is pinned; nothing asks again.
    ///
    /// # Errors
    ///
    /// Returns [`Error::RemoteSigner`](ghostr_crypto::Error::RemoteSigner) if
    /// the signer refuses the connection, does not answer, or returns a pubkey
    /// that is not a valid curve point.
    pub async fn connect(
        transport: T,
        signer_pubkey: &PublicKey,
        secret: Option<String>,
        account: Account,
        session: String,
    ) -> crate::Result<Self> {
        let unconnected = Self {
            transport,
            // A placeholder only until `get_public_key` answers. Nothing signs
            // in between: `connect` and `get_public_key` are the only calls made
            // before it is replaced.
            user_pubkey: *signer_pubkey,
            account,
            session,
            next_id: AtomicU64::new(0),
        };

        let mut params = vec![signer_pubkey.to_hex()];
        if let Some(secret) = secret {
            params.push(secret);
        }
        unconnected.call(Method::Connect, params).await?;

        let hex = unconnected.call(Method::GetPublicKey, Vec::new()).await?;
        let user_pubkey = parse_pubkey(&hex)?;

        Ok(Self {
            user_pubkey,
            ..unconnected
        })
    }

    /// The user's public key, as the signer reported it at connect time.
    #[must_use]
    pub const fn user_pubkey(&self) -> &PublicKey {
        &self.user_pubkey
    }

    /// Checks the signer is alive.
    ///
    /// # Errors
    ///
    /// Returns [`Error::RemoteSigner`](ghostr_crypto::Error::RemoteSigner) if it
    /// does not answer `pong`.
    pub async fn ping(&self) -> crate::Result<()> {
        if self.call(Method::Ping, Vec::new()).await? == "pong" {
            Ok(())
        } else {
            Err(remote("signer did not answer ping"))
        }
    }

    /// Sends one request and returns its `result`.
    async fn call(&self, method: Method, params: Vec<String>) -> crate::Result<String> {
        let id = format!(
            "{}-{}",
            self.session,
            self.next_id.fetch_add(1, Ordering::Relaxed)
        );
        let request = Request {
            id: id.clone(),
            method: method.as_str(),
            params,
        };
        let encoded =
            serde_json::to_string(&request).map_err(|_| remote("request did not serialise"))?;

        let raw = self.transport.round_trip(&encoded).await?;
        let response: Response =
            serde_json::from_str(&raw).map_err(|_| remote("signer sent a malformed response"))?;

        // Correlation is a guard, not bookkeeping. Without it one reply can be
        // read as the answer to a different question — a `get_public_key`
        // answered by a stale `sign_event` reply, say.
        if response.id != id {
            return Err(remote("signer answered a different request"));
        }

        // The signer's error text is attacker-influenced and never interpolated
        // into ours: `Error::RemoteSigner` takes a `&'static str`, which makes
        // that impossible rather than merely discouraged.
        if response.error.is_some() {
            return Err(remote("signer refused the request"));
        }
        response
            .result
            .ok_or_else(|| remote("signer sent neither a result nor an error"))
    }

    /// Refuses an account this signer does not hold.
    fn check(&self, key: KeyRef) -> crate::Result<()> {
        if key.account == self.account {
            Ok(())
        } else {
            Err(remote("this signer holds a different key"))
        }
    }
}

/// Builds the one error shape a remote signer produces.
fn remote(reason: &'static str) -> crate::Error {
    crate::Error::Crypto(CryptoError::RemoteSigner { reason })
}

/// Parses a hex pubkey from a signer.
fn parse_pubkey(hex_str: &str) -> crate::Result<PublicKey> {
    let bytes =
        hex::decode(hex_str.trim()).map_err(|_| remote("signer sent a malformed pubkey"))?;
    let array: [u8; 32] = bytes
        .try_into()
        .map_err(|_| remote("signer sent a pubkey of the wrong length"))?;
    Ok(PublicKey::from_bytes(array))
}

#[async_trait]
impl<T: Nip46Transport> Signer for Nip46Signer<T> {
    fn public_key(&self, key: KeyRef) -> ghostr_crypto::Result<PublicKey> {
        // Answered from the pinned value rather than by asking. A signer that
        // reports a different key mid-session has switched identity, and every
        // signature after that point would be someone else's.
        match self.check(key) {
            Ok(()) => Ok(self.user_pubkey),
            Err(_) => Err(CryptoError::RemoteSigner {
                reason: "this signer holds a different key",
            }),
        }
    }

    async fn sign_event(
        &self,
        key: KeyRef,
        event: &UnsignedEvent,
    ) -> ghostr_crypto::Result<Signature> {
        self.check(key).map_err(|_| CryptoError::RemoteSigner {
            reason: "this signer holds a different key",
        })?;
        if event.pubkey != self.user_pubkey {
            return Err(CryptoError::KeyMismatch);
        }

        let body = serde_json::json!({
            "kind": event.kind,
            "content": event.content,
            "tags": event.tags,
            "created_at": event.created_at,
        })
        .to_string();

        let raw = self
            .call(Method::SignEvent, vec![body])
            .await
            .map_err(|_| CryptoError::RemoteSigner {
                reason: "signer did not sign",
            })?;

        // NIP-46 returns the whole signed event, not a signature. That is the
        // dangerous shape: a signer can return a *different* event, correctly
        // signed, and a client that takes the `sig` field on trust would publish
        // it as its own. The id is a hash of the body, so an id equal to the one
        // we computed means the body is byte-for-byte ours.
        let signed: SignedEvent =
            serde_json::from_str(&raw).map_err(|_| CryptoError::RemoteSigner {
                reason: "signer sent a malformed event",
            })?;

        if signed.id != event.id() {
            return Err(CryptoError::RemoteSigner {
                reason: "signer signed a different event",
            });
        }
        if signed.event.pubkey != self.user_pubkey {
            return Err(CryptoError::RemoteSigner {
                reason: "signer used a different key",
            });
        }
        // And the signature must actually verify. Matching ids prove the body;
        // this proves the signature over it is real rather than noise.
        signed.verify()?;

        Ok(signed.sig)
    }

    async fn nip44_encrypt(
        &self,
        key: KeyRef,
        recipient: &PublicKey,
        plaintext: &[u8],
        _nonce: [u8; 32],
    ) -> ghostr_crypto::Result<String> {
        self.check(key).map_err(|_| CryptoError::RemoteSigner {
            reason: "this signer holds a different key",
        })?;

        // The nonce is ignored, and that is the protocol's choice rather than
        // ours: NIP-46's `nip44_encrypt` takes only a pubkey and a plaintext, so
        // the remote signer draws its own. The parameter stays in the signature
        // because a local keystore does need it, and a trait whose shape changes
        // per implementation is not a seam.
        let text = core::str::from_utf8(plaintext).map_err(|_| CryptoError::InvalidPublicKey)?;

        self.call(
            Method::Nip44Encrypt,
            vec![recipient.to_hex(), text.to_owned()],
        )
        .await
        .map_err(|_| CryptoError::RemoteSigner {
            reason: "signer did not encrypt",
        })
    }

    async fn nip44_decrypt(
        &self,
        key: KeyRef,
        sender: &PublicKey,
        payload: &str,
    ) -> ghostr_crypto::Result<Vec<u8>> {
        self.check(key).map_err(|_| CryptoError::RemoteSigner {
            reason: "this signer holds a different key",
        })?;

        let plaintext = self
            .call(
                Method::Nip44Decrypt,
                vec![sender.to_hex(), payload.to_owned()],
            )
            .await
            .map_err(|_| CryptoError::DecryptFailed)?;
        Ok(plaintext.into_bytes())
    }
}
