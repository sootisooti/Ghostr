//! The two seams: [`Signer`] and [`Keystore`].
//!
//! Both are traits so that the local keystore, a NIP-46 remote signer
//! ("bunker"), and a hardware device are interchangeable. That matters more than
//! it looks: it is what lets a user keep the identity key off the machine that
//! runs the agent, which is the recommended configuration for anyone who
//! publishes (THREAT_MODEL §T5).

use async_trait::async_trait;
use ghostr_core::identity::{Account, KeyRef, PublicKey};

use crate::event::{Signature, UnsignedEvent};
use crate::kdf::Dek;
use crate::keystore::WrapEntropy;
use crate::secret::SecretString;

/// Anything that can produce a nostr signature.
///
/// Note what is absent: **no method returns key material.** Callers name a key
/// with a [`KeyRef`] and ask for an operation, which is why a remote signer is a
/// drop-in rather than a rewrite.
///
/// That is a constraint on this trait's shape, not a description of its
/// implementations. A method returning a derived secret is one a bunker or a
/// hardware wallet could only refuse, and a method the intended implementations
/// must refuse is a hole rather than a seam — see the note below the trait.
///
/// `ghostr-nostr/tests/external_signer.rs` crosses the seam for real: it drives
/// the event codec through an implementation with no vault, no store and no
/// keystore file.
#[async_trait]
pub trait Signer: Send + Sync {
    /// The public key for a reference.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Locked`](crate::Error::Locked) if the backing keystore
    /// is locked.
    fn public_key(&self, key: KeyRef) -> crate::Result<PublicKey>;

    /// Signs an event, computing its id first.
    ///
    /// The id is derived from the event body here, never accepted from the
    /// caller: a signer that signs a digest it was handed will happily
    /// authenticate a body it never saw.
    ///
    /// Async because the signer may be a remote process or a hardware device
    /// waiting on a physical confirmation.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Locked`](crate::Error::Locked) if locked,
    /// [`Error::KeyMismatch`](crate::Error::KeyMismatch) if `key` is not the
    /// event's stated author, or
    /// [`Error::RemoteSigner`](crate::Error::RemoteSigner) if a remote signer is
    /// unreachable or declined.
    async fn sign_event(&self, key: KeyRef, event: &UnsignedEvent) -> crate::Result<Signature>;

    /// NIP-44 v2 encryption to `recipient`.
    ///
    /// Conversation key derivation stays inside the implementation, because it
    /// needs the secret key. Pass the signer's own public key as `recipient` for
    /// self-encryption.
    ///
    /// `nonce` is a parameter rather than drawn here, for the same reason
    /// [`FileKeystore::create`](crate::FileKeystore::create) takes its salt:
    /// entropy is confined to the composition root, which holds the
    /// [`Rng`](ghostr_core::time::Rng) (CLAUDE.md §6). It **must** be fresh for
    /// every message under one conversation key — NIP-44 derives the keystream
    /// from it, so a repeat is a two-time pad.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Locked`](crate::Error::Locked) if locked, or
    /// [`Error::InvalidPublicKey`](crate::Error::InvalidPublicKey) if
    /// `recipient` is not a curve point.
    async fn nip44_encrypt(
        &self,
        key: KeyRef,
        recipient: &PublicKey,
        plaintext: &[u8],
        nonce: [u8; 32],
    ) -> crate::Result<String>;

    /// NIP-44 v2 decryption.
    ///
    /// # Errors
    ///
    /// Returns [`Error::DecryptFailed`](crate::Error::DecryptFailed) for any
    /// decryption failure, without distinguishing the cause.
    async fn nip44_decrypt(
        &self,
        key: KeyRef,
        sender: &PublicKey,
        payload: &str,
    ) -> crate::Result<Vec<u8>>;

    /// Wraps a rumor in NIP-59 gift wrap, returning the finished kind-1059.
    ///
    /// # Why this is one method rather than a signing primitive
    ///
    /// Gift wrap is three layers: the **rumor** (unsigned, the real content), a
    /// **seal** (kind 13) encrypted to the recipient and signed by the real
    /// author, and a **wrap** (kind 1059) encrypted and signed by a throwaway
    /// key that exists for exactly one event. That throwaway key is the whole
    /// mechanism — it is what hides the author from a relay.
    ///
    /// It is therefore born, used and zeroized inside this crate and never
    /// crosses a boundary, which is the same treatment the identity key gets
    /// (SPEC §11.3). The alternative — a general "sign these bytes with this
    /// ephemeral key" primitive — was rejected: that is a signing oracle for
    /// arbitrary bytes under a caller-chosen key, and this would be its only
    /// caller.
    ///
    /// A remote signer can implement this: nothing here returns key material.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Locked`](crate::Error::Locked) if locked,
    /// [`Error::InvalidPublicKey`](crate::Error::InvalidPublicKey) if the
    /// ephemeral entropy is not a usable scalar or `recipient` is not a curve
    /// point, or [`Error::Backend`](crate::Error::Backend) if the rumor carries
    /// a timestamp the layers above it would have to precede.
    async fn gift_wrap(
        &self,
        key: KeyRef,
        recipient: &PublicKey,
        rumor: &UnsignedEvent,
        entropy: GiftWrapEntropy,
    ) -> crate::Result<crate::event::SignedEvent>;
}

/// The randomness and timestamps one gift wrap needs.
///
/// Bundled because the values are correlated and all five have to come from the
/// composition root: an ephemeral secret, a nonce for each of the two
/// encryptions, and a `created_at` for each of the two outer layers.
///
/// # The timestamps go backwards, and that is not the same as publish jitter
///
/// NIP-59 §"canonical time": the rumor holds the real `created_at`, and every
/// other layer SHOULD be tweaked **into the past** — partly to thwart time
/// analysis, partly because relays refuse events dated in the future. The seal
/// and the wrap SHOULD get *independent* values, so a relay cannot pair them by
/// timestamp.
///
/// This runs opposite to `ghostr-nostr`'s publish jitter, which only ever moves
/// a timestamp *later*, and the two are not in conflict: jitter hides when a
/// footage was sealed by delaying its publication, while this hides who wrote a
/// wrapped event by decorrelating its layers.
pub struct GiftWrapEntropy {
    /// Secret scalar for the throwaway key. Zeroized after use.
    pub ephemeral_secret: [u8; 32],
    /// NIP-44 nonce for the seal.
    pub seal_nonce: [u8; 32],
    /// NIP-44 nonce for the wrap. Must differ from `seal_nonce`.
    pub wrap_nonce: [u8; 32],
    /// `created_at` for the seal. At or before the rumor's.
    pub seal_created_at: u64,
    /// `created_at` for the wrap. At or before the rumor's, and independent of
    /// the seal's.
    pub wrap_created_at: u64,
}

impl core::fmt::Debug for GiftWrapEntropy {
    /// Never prints the ephemeral secret: it is key material, and a leaked one
    /// deanonymises the author of every event wrapped under it.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("GiftWrapEntropy")
            .field("seal_created_at", &self.seal_created_at)
            .field("wrap_created_at", &self.wrap_created_at)
            .finish_non_exhaustive()
    }
}

// There is deliberately no `conversation_key` on this trait.
//
// It used to be here, as an optimisation for callers encrypting many payloads
// to one recipient. It returned a `ConversationKey`, which is key material —
// contradicting this trait's own opening line, seventy lines above, in the same
// file.
//
// The contradiction is not cosmetic. A NIP-46 bunker or a hardware wallet exists
// precisely so derived secrets never leave it; such a signer could only refuse
// the method, and a trait method the intended implementations must refuse is not
// a seam, it is a hole. Nothing outside `ghostr-crypto` ever called it.
//
// `FileKeystore` keeps it as an inherent method, where it is a local
// implementation detail rather than a promise made to every signer.

/// Holds wrapped secrets and hands out references to them.
///
/// Locking is a first-class state, not an afterthought: the daily loop runs
/// unattended, and an idle auto-lock is the only thing standing between an
/// unlocked corpus and whoever sits down at the machine next (THREAT_MODEL §T6).
pub trait Keystore: Send + Sync {
    /// Derives the KEK and unwraps the DEK.
    ///
    /// # Errors
    ///
    /// Returns [`Error::BadPassphrase`](crate::Error::BadPassphrase) if the
    /// passphrase does not unwrap the DEK. Callers must rate-limit: Argon2id
    /// makes each attempt expensive, which only helps if attempts are serial.
    fn unlock(&mut self, passphrase: SecretString) -> crate::Result<()>;

    /// Zeroizes the KEK and DEK and returns to the locked state.
    fn lock(&mut self);

    /// Whether the keystore is currently locked.
    fn is_locked(&self) -> bool;

    /// A reference to one NIP-06 account's key.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Locked`](crate::Error::Locked) if locked.
    fn key_ref(&self, account: Account) -> crate::Result<KeyRef>;

    /// Borrows the data encryption key, for the store to encrypt rows with.
    ///
    /// The one place a raw key crosses a crate boundary, and it is deliberate:
    /// `ghostr-store` encrypts every row it writes and cannot do that through a
    /// per-operation trait call without a per-row round trip. The DEK is still
    /// zeroizing and still owned by the keystore; the store borrows it.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Locked`](crate::Error::Locked) if locked.
    fn dek(&self) -> crate::Result<&Dek>;

    /// Re-wraps the vault's secrets under a new passphrase.
    ///
    /// Cheap by design: the corpus is encrypted under the DEK, which this does
    /// not change. What gets rewrapped is the 64-byte seed — and, in a vault
    /// whose identity was imported, the 32-byte identity key beside it. Both or
    /// neither: a vault that rewraps one is one whose identity or whose journal
    /// is unreachable.
    ///
    /// # Why the old passphrase, and why the entropy
    ///
    /// `old_passphrase` is required so this is an *authorised* operation rather
    /// than something a passer-by can do to an unlocked laptop. Being unlocked
    /// already gives an attacker the contents; it should not also hand them the
    /// ability to lock the owner out.
    ///
    /// `entropy` is supplied rather than drawn because `OsRng` belongs in the
    /// composition root (SPEC §11.4, CLAUDE.md §6), and because reusing the
    /// stored salt would wrap a new KEK under parameters chosen for an old one
    /// — letting anyone holding a copy of the old file test one guess against
    /// both wrappings for the price of a single derivation.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Locked`](crate::Error::Locked) if locked,
    /// [`Error::BadPassphrase`](crate::Error::BadPassphrase) if
    /// `old_passphrase` is wrong, or
    /// [`Error::Backend`](crate::Error::Backend) if the new wrapping cannot be
    /// persisted. On any error the stored file is left exactly as it was.
    fn change_passphrase(
        &mut self,
        old_passphrase: SecretString,
        new_passphrase: SecretString,
        entropy: WrapEntropy,
    ) -> crate::Result<()>;
}
