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
