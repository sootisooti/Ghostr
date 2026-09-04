//! The on-disk keystore, and the local [`Keystore`] implementation.
//!
//! The file holds a KEK-wrapped BIP-39 seed and nothing else that matters. It
//! deliberately does **not** hold the data encryption key: that is derived from
//! the identity secret key on unlock (SPEC §10.1), so there is no second secret
//! to back up and nothing on disk that could leak it.
//!
//! The public key and npub are stored in the clear. They are public by
//! definition, and having them readable while locked is what lets
//! `ghostr status` say whose vault this is without a passphrase.

use std::path::{Path, PathBuf};

use async_trait::async_trait;
use ghostr_core::identity::{Account, KeyRef, Npub, PublicKey};
use serde::{Deserialize, Serialize};

use crate::event::{Signature, UnsignedEvent};
use crate::kdf::{
    Argon2Params, Dek, WrappedSeed, derive_dek, derive_kek, unwrap_identity, unwrap_seed,
    wrap_identity, wrap_seed,
};
use crate::nip06::{DerivedKey, MasterKey, Mnemonic};
use crate::nip44::ConversationKey;
use crate::secret::SecretString;
use crate::signer::{Keystore, Signer};

/// Where a vault's data encryption key comes from.
///
/// # Why this is written down rather than inferred
///
/// SPEC §10.1 originally derived the DEK from the **identity** secret key, so
/// the store was readable exactly when the identity was unlocked and there was
/// no second secret to back up. That is a good property and it has a
/// consequence nobody wrote down: a vault whose identity key lives on a hardware
/// wallet **cannot be decrypted at all**. The app holds a pubkey and a signing
/// oracle, and no amount of asking that oracle to sign produces the 32 bytes
/// HKDF needs.
///
/// So new vaults derive from [`Account::Data`] instead, which the seed already
/// produces and nothing else uses. Existing vaults keep what they have —
/// changing where an existing DEK comes from would re-encrypt every row
/// (CLAUDE.md §4.7), so the file records the scheme and migration is a
/// deliberate act rather than a side effect of an upgrade.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum DekSource {
    /// HKDF of the identity secret key. Version 1 vaults.
    ///
    /// Cannot support an external signer: the identity secret never reaches this
    /// process, and there is no other way to reach the DEK.
    Identity,
    /// HKDF of the `Account::Data` secret key. Version 2 and later.
    ///
    /// Independent of how the identity key is held, which is what makes an
    /// imported `nsec` or a hardware signer possible (SPEC §14 Q21).
    VaultData,
}

impl DekSource {
    /// What a file without the field means.
    ///
    /// Version 1 predates the field, and every version 1 vault derives from the
    /// identity key. Defaulting to [`DekSource::VaultData`] would make every
    /// existing vault fail to decrypt with a wrong-passphrase error, which is
    /// the least debuggable failure this crate can produce.
    const fn legacy() -> Self {
        Self::Identity
    }
}

/// How a vault's identity key is held.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum IdentitySource {
    /// Derived from the vault seed at `m/44'/1237'/0'/0/0`, as NIP-06 says.
    Seed,
    /// An `nsec` the user brought, wrapped beside the seed.
    ///
    /// The vault seed still exists and still produces ghost, anchor and data —
    /// an `nsec` is a raw key with no tree under it, so there is nothing to
    /// derive those from (SPEC §14 Q21).
    ImportedNsec,
}

/// The randomness a keystore's wrapping needs.
///
/// Bundled rather than passed loose because the three values are correlated:
/// two secrets wrapped under one KEK must not share a nonce, or they share a
/// keystream. [`WrapEntropy::new`] is the only constructor and it refuses that
/// case, so a caller cannot hold an invalid combination to pass on — the check
/// is in the type rather than in every function that takes one.
///
/// Drawn by the caller, never here, so `init` stays reproducible under a seeded
/// RNG and entropy stays in the composition root (ARCHITECTURE §4.7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WrapEntropy {
    salt: [u8; 16],
    seed_nonce: [u8; 24],
    identity_nonce: [u8; 24],
}

impl WrapEntropy {
    /// Checks the two nonces differ.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Backend`](crate::Error::Backend) if they are equal.
    pub fn new(
        salt: [u8; 16],
        seed_nonce: [u8; 24],
        identity_nonce: [u8; 24],
    ) -> crate::Result<Self> {
        if seed_nonce == identity_nonce {
            return Err(crate::Error::Backend {
                operation: "seed and identity nonces must differ",
            });
        }
        Ok(Self {
            salt,
            seed_nonce,
            identity_nonce,
        })
    }

    /// The Argon2id salt.
    #[must_use]
    pub const fn salt(&self) -> [u8; 16] {
        self.salt
    }

    /// The nonce for the wrapped seed.
    #[must_use]
    pub const fn seed_nonce(&self) -> [u8; 24] {
        self.seed_nonce
    }

    /// The nonce for a wrapped imported identity key.
    #[must_use]
    pub const fn identity_nonce(&self) -> [u8; 24] {
        self.identity_nonce
    }
}

/// The keystore file format.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeystoreFile {
    /// Format version, so a future change can migrate rather than misread.
    pub version: u32,
    /// The wrapped seed and the parameters needed to unwrap it.
    pub seed: WrappedSeed,
    /// The identity public key, in hex. Public by definition.
    pub identity_pubkey: String,
    /// The identity npub. Stored so a locked vault can still say whose it is.
    pub npub: String,
    /// Where the DEK comes from. Absent in version 1 files.
    #[serde(default = "DekSource::legacy")]
    pub dek_source: DekSource,
    /// How the identity key is held. Absent in version 1 files.
    #[serde(default = "IdentitySource::seed")]
    pub identity_source: IdentitySource,
    /// The imported identity key, wrapped under the same KEK as the seed.
    ///
    /// Present only when [`KeystoreFile::identity_source`] is
    /// [`IdentitySource::ImportedNsec`]. Wrapped rather than stored, and under
    /// the same KEK, so a passphrase protects both halves or neither.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_key: Option<WrappedSeed>,
}

impl IdentitySource {
    /// What a file without the field means: the pre-import behaviour.
    const fn seed() -> Self {
        Self::Seed
    }
}

/// The current keystore format version.
///
/// Bumped to 2 when the DEK moved off the identity key. A version 1 file still
/// opens and still works; it simply cannot adopt an external signer.
pub const KEYSTORE_VERSION: u32 = 2;

/// The keystore filename inside the data directory.
pub const KEYSTORE_FILENAME: &str = "keystore.json";

/// A keystore backed by a file, unlocked into process memory.
pub struct FileKeystore {
    path: PathBuf,
    file: KeystoreFile,
    unlocked: Option<Unlocked>,
}

/// The material that exists only while unlocked.
struct Unlocked {
    keys: Vec<DerivedKey>,
    dek: Dek,
}

impl core::fmt::Debug for FileKeystore {
    /// Prints the path and lock state, never key material (SPEC I8).
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("FileKeystore")
            .field("path", &self.path)
            .field("locked", &self.unlocked.is_none())
            .finish()
    }
}

impl FileKeystore {
    /// Creates a keystore, wrapping `mnemonic` under `passphrase`.
    ///
    /// Nonce and salt are parameters rather than generated here, so `init` is
    /// reproducible under a seeded RNG in tests and entropy stays confined to
    /// the composition root (ARCHITECTURE §4.7).
    ///
    /// # Errors
    ///
    /// Returns [`Error::Backend`](crate::Error::Backend) if the file cannot be
    /// written, or a derivation error if the mnemonic is unusable.
    pub fn create(
        path: &Path,
        mnemonic: &Mnemonic,
        passphrase: &SecretString,
        salt: [u8; 16],
        nonce: [u8; 24],
        params: Argon2Params,
    ) -> crate::Result<Self> {
        let seed = mnemonic.to_seed(None)?;
        let master = MasterKey::from_seed(&seed)?;
        let identity = master.derive_account(Account::Identity)?;
        let kek = derive_kek(passphrase, &salt, params)?;
        let wrapped = wrap_seed(&kek, &seed, &nonce, &salt, params)?;

        let file = KeystoreFile {
            version: KEYSTORE_VERSION,
            seed: wrapped,
            identity_pubkey: identity.public.to_hex(),
            npub: crate::nip19::encode_npub(&identity.public)
                .as_str()
                .to_owned(),
            // New vaults derive the DEK from the vault seed, so the identity key
            // can later move to hardware without re-encrypting anything.
            dek_source: DekSource::VaultData,
            identity_source: IdentitySource::Seed,
            identity_key: None,
        };
        let json = serde_json::to_string_pretty(&file).map_err(|_| crate::Error::Backend {
            operation: "serialise keystore",
        })?;
        write_private(path, json.as_bytes())?;
        Ok(Self {
            path: path.to_path_buf(),
            file,
            unlocked: None,
        })
    }

    /// Creates a vault whose identity is an `nsec` the user already had.
    ///
    /// # What is and is not imported
    ///
    /// Only the identity. Ghost, anchor and data still come from a freshly
    /// generated vault seed, because an `nsec` is a raw key with no BIP-32 tree
    /// under it — there is nothing to derive them from (SPEC §14 Q21). The DEK
    /// comes from the vault seed too, so this vault keeps working if the same
    /// key later moves to a hardware signer that will never hand over its bytes.
    ///
    /// The two halves are wrapped under the same KEK, so one passphrase protects
    /// both or neither, and under different AAD, so neither can be pasted over
    /// the other.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidPublicKey`](crate::Error::InvalidPublicKey) if
    /// the key is not a usable secp256k1 scalar, or
    /// [`Error::Backend`](crate::Error::Backend) if the file cannot be written.
    pub fn create_with_nsec(
        path: &Path,
        identity_secret: crate::secret::SecretBytes<32>,
        mnemonic: &Mnemonic,
        passphrase: &SecretString,
        entropy: WrapEntropy,
        params: Argon2Params,
    ) -> crate::Result<Self> {
        // Refused here rather than at the first signature: an unusable key
        // should fail while the user still has the `nsec` in front of them.
        let identity = DerivedKey::from_secret(Account::Identity, *identity_secret.expose())?;

        let salt = entropy.salt;
        let seed = mnemonic.to_seed(None)?;
        let kek = derive_kek(passphrase, &salt, params)?;
        let wrapped_seed = wrap_seed(&kek, &seed, &entropy.seed_nonce, &salt, params)?;
        let wrapped_identity = wrap_identity(
            &kek,
            &identity_secret,
            &entropy.identity_nonce,
            &salt,
            params,
        )?;

        let file = KeystoreFile {
            version: KEYSTORE_VERSION,
            seed: wrapped_seed,
            identity_pubkey: identity.public.to_hex(),
            npub: crate::nip19::encode_npub(&identity.public)
                .as_str()
                .to_owned(),
            dek_source: DekSource::VaultData,
            identity_source: IdentitySource::ImportedNsec,
            identity_key: Some(wrapped_identity),
        };
        let json = serde_json::to_string_pretty(&file).map_err(|_| crate::Error::Backend {
            operation: "serialise keystore",
        })?;
        write_private(path, json.as_bytes())?;
        Ok(Self {
            path: path.to_path_buf(),
            file,
            unlocked: None,
        })
    }

    /// Opens an existing keystore, locked.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Backend`](crate::Error::Backend) if the file is missing
    /// or malformed.
    pub fn open(path: &Path) -> crate::Result<Self> {
        let bytes = std::fs::read(path).map_err(|_| crate::Error::Backend {
            operation: "read keystore",
        })?;
        let file: KeystoreFile =
            serde_json::from_slice(&bytes).map_err(|_| crate::Error::Backend {
                operation: "parse keystore",
            })?;
        if file.version > KEYSTORE_VERSION {
            // Refuse rather than guess: writing with an older understanding of
            // the format could strand a seed nothing can unwrap.
            return Err(crate::Error::Backend {
                operation: "keystore is from a newer version",
            });
        }
        Ok(Self {
            path: path.to_path_buf(),
            file,
            unlocked: None,
        })
    }

    /// Whether a keystore exists at `path`.
    #[must_use]
    pub fn exists(path: &Path) -> bool {
        path.is_file()
    }

    /// The identity public key. Available while locked.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Backend`](crate::Error::Backend) if the stored key is
    /// malformed.
    pub fn identity_pubkey(&self) -> crate::Result<PublicKey> {
        PublicKey::from_hex(&self.file.identity_pubkey).map_err(|_| crate::Error::Backend {
            operation: "parse stored pubkey",
        })
    }

    /// The identity npub. Available while locked.
    #[must_use]
    pub fn npub(&self) -> Npub {
        Npub::from_encoded(self.file.npub.clone())
    }

    /// The derived key for one account.
    ///
    /// Private, and returns a borrow rather than a copy: this is the only path
    /// from a [`KeyRef`] to actual secret bytes, and every caller is in this
    /// file (ARCHITECTURE §3 rule 4).
    fn derived(&self, account: Account) -> crate::Result<&DerivedKey> {
        self.unlocked
            .as_ref()
            .ok_or(crate::Error::Locked)?
            .keys
            .iter()
            .find(|k| k.account == account)
            .ok_or(crate::Error::InvalidDerivationPath)
    }

    /// The public key for one account. Requires unlocking.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Locked`](crate::Error::Locked) if locked.
    pub fn account_pubkey(&self, account: Account) -> crate::Result<PublicKey> {
        Ok(self.derived(account)?.public)
    }
}

/// Writes a file that only the owner can read.
///
/// The keystore is the single most valuable file on the disk. Creating it
/// world-readable for even a moment is a real window, so the mode is set at
/// creation rather than afterwards.
fn write_private(path: &Path, bytes: &[u8]) -> crate::Result<()> {
    use std::io::Write as _;

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|_| crate::Error::Backend {
            operation: "create data directory",
        })?;
    }

    // Written to a sibling and renamed, rather than truncated in place.
    //
    // Truncating is fine the first time, when there is nothing to lose. It is
    // not fine for a passphrase change: the file holds the only copy of the
    // wrapped seed, and a crash between truncate and write leaves a vault whose
    // corpus can never be decrypted again. `rename` within a directory is
    // atomic on POSIX, so a reader sees either the old file or the new one.
    let temporary = path.with_extension("new");

    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut f = options
        .open(&temporary)
        .map_err(|_| crate::Error::Backend {
            operation: "open keystore for writing",
        })?;
    f.write_all(bytes).map_err(|_| crate::Error::Backend {
        operation: "write keystore",
    })?;
    // Before the rename, not after: a rename that lands before the bytes reach
    // the disk can publish an empty file.
    f.sync_all().map_err(|_| crate::Error::Backend {
        operation: "sync keystore",
    })?;
    drop(f);

    std::fs::rename(&temporary, path).map_err(|_| crate::Error::Backend {
        operation: "replace keystore",
    })?;

    // And the directory entry itself, so the rename survives a power loss.
    #[cfg(unix)]
    if let Some(dir) = path.parent().and_then(|p| std::fs::File::open(p).ok()) {
        let _ = dir.sync_all();
    }
    Ok(())
}

impl Keystore for FileKeystore {
    fn unlock(&mut self, passphrase: SecretString) -> crate::Result<()> {
        let kek = derive_kek(&passphrase, &self.file.seed.salt, self.file.seed.params)?;
        let seed = unwrap_seed(&kek, &self.file.seed)?;
        let master = MasterKey::from_seed(&seed)?;

        let mut keys = [
            Account::Identity,
            Account::Ghost,
            Account::Anchor,
            Account::Data,
            Account::SignerChannel,
        ]
        .into_iter()
        .map(|a| master.derive_account(a))
        .collect::<crate::Result<Vec<_>>>()?;

        // An imported identity replaces the one the seed produced. Ghost, anchor
        // and data keep coming from the seed — an `nsec` has no tree under it.
        if self.file.identity_source == IdentitySource::ImportedNsec {
            let wrapped = self
                .file
                .identity_key
                .as_ref()
                .ok_or(crate::Error::Backend {
                    operation: "keystore claims an imported identity but carries none",
                })?;
            let secret = unwrap_identity(&kek, wrapped)?;
            for key in &mut keys {
                if key.account == Account::Identity {
                    *key = DerivedKey::from_secret(Account::Identity, *secret.expose())?;
                }
            }
        }

        let identity = keys
            .iter()
            .find(|k| k.account == Account::Identity)
            .ok_or(crate::Error::InvalidDerivationPath)?;

        // A keystore whose wrapped seed derives a different identity than the one
        // recorded has been tampered with or swapped. Catch it here rather than
        // letting the store fail to decrypt with a confusing error.
        if identity.public.to_hex() != self.file.identity_pubkey {
            return Err(crate::Error::Backend {
                operation: "keystore identity mismatch",
            });
        }

        // Whichever key the file says, never whichever is convenient. Guessing
        // here would decrypt nothing and report a wrong passphrase, which is the
        // least debuggable failure this crate can produce.
        let dek = match self.file.dek_source {
            DekSource::Identity => derive_dek(identity.secret_bytes()),
            DekSource::VaultData => {
                let data = keys
                    .iter()
                    .find(|k| k.account == Account::Data)
                    .ok_or(crate::Error::InvalidDerivationPath)?;
                derive_dek(data.secret_bytes())
            }
        };

        self.unlocked = Some(Unlocked { keys, dek });
        Ok(())
    }

    fn lock(&mut self) {
        // Dropping zeroizes: DerivedKey holds SecretBytes and Dek wraps one.
        self.unlocked = None;
    }

    fn is_locked(&self) -> bool {
        self.unlocked.is_none()
    }

    fn key_ref(&self, account: Account) -> crate::Result<KeyRef> {
        if self.is_locked() {
            return Err(crate::Error::Locked);
        }
        Ok(KeyRef { account })
    }

    fn dek(&self) -> crate::Result<&Dek> {
        self.unlocked
            .as_ref()
            .map(|u| &u.dek)
            .ok_or(crate::Error::Locked)
    }

    fn change_passphrase(
        &mut self,
        old_passphrase: SecretString,
        new_passphrase: SecretString,
        entropy: WrapEntropy,
    ) -> crate::Result<()> {
        // The old passphrase is not checked and then trusted — it is the only
        // way to reach the seed at all, so authorisation here is structural
        // rather than a guard someone could later delete "to simplify". A
        // rewrap needs the plaintext seed, and the plaintext seed exists only
        // on the far side of this unwrap.
        //
        // That is why it also stops a passer-by re-keying an unlocked laptop:
        // being unlocked hands an attacker the contents, and it should not also
        // hand them the ability to lock the owner out.
        let old_kek = derive_kek(&old_passphrase, &self.file.seed.salt, self.file.seed.params)?;
        let seed = unwrap_seed(&old_kek, &self.file.seed)?;

        let imported = match self.file.identity_source {
            IdentitySource::ImportedNsec => {
                let wrapped = self
                    .file
                    .identity_key
                    .as_ref()
                    .ok_or(crate::Error::Backend {
                        operation: "keystore claims an imported identity but carries none",
                    })?;
                Some(unwrap_identity(&old_kek, wrapped)?)
            }
            IdentitySource::Seed => None,
        };

        let salt = entropy.salt();
        let new_kek = derive_kek(&new_passphrase, &salt, self.file.seed.params)?;
        let wrapped_seed = wrap_seed(
            &new_kek,
            &seed,
            &entropy.seed_nonce(),
            &salt,
            self.file.seed.params,
        )?;
        let wrapped_identity = imported
            .map(|key| {
                wrap_identity(
                    &new_kek,
                    &key,
                    &entropy.identity_nonce(),
                    &salt,
                    self.file.seed.params,
                )
            })
            .transpose()?;

        // Both wrappings are built before either is stored, so a failure part
        // way through leaves the file untouched rather than half re-keyed. The
        // write itself is atomic (see `write_private`), which is what makes
        // "untouched" true even across a crash.
        let mut updated = self.file.clone();
        updated.seed = wrapped_seed;
        if wrapped_identity.is_some() {
            updated.identity_key = wrapped_identity;
        }

        let json = serde_json::to_string_pretty(&updated).map_err(|_| crate::Error::Backend {
            operation: "serialise keystore",
        })?;
        write_private(&self.path, json.as_bytes())?;
        self.file = updated;

        // The unlocked state is deliberately kept. The DEK is derived from key
        // material the passphrase does not touch, so the vault stays readable
        // and the user is not logged out of an operation they just authorised.
        Ok(())
    }
}

/// The local signer.
///
/// `FileKeystore` is both [`Keystore`] and [`Signer`] because the secret bytes
/// it unwraps never leave it: the keys live in the private unlocked state, and
/// every operation that needs one happens here. A remote signer implements only
/// this half.
#[async_trait]
impl Signer for FileKeystore {
    fn public_key(&self, key: KeyRef) -> crate::Result<PublicKey> {
        self.account_pubkey(key.account)
    }

    async fn sign_event(&self, key: KeyRef, event: &UnsignedEvent) -> crate::Result<Signature> {
        let derived = self.derived(key.account)?;

        // The event names its author and NIP-01 verifies against *that* key, so
        // signing with a different one produces something nobody can validate.
        // Caught here, where both keys are in hand, rather than at a relay.
        if derived.public != event.pubkey {
            return Err(crate::Error::KeyMismatch);
        }

        // The id comes from the body, every time. This is the whole reason
        // `sign_event` takes an event rather than a digest.
        derived.sign(event.id().as_bytes())
    }

    async fn nip44_encrypt(
        &self,
        key: KeyRef,
        recipient: &PublicKey,
        plaintext: &[u8],
        nonce: [u8; 32],
    ) -> crate::Result<String> {
        let conversation = self.conversation_key(key, recipient)?;
        crate::nip44::encrypt(&conversation, plaintext, &nonce)
    }

    async fn nip44_decrypt(
        &self,
        key: KeyRef,
        sender: &PublicKey,
        payload: &str,
    ) -> crate::Result<Vec<u8>> {
        let conversation = self.conversation_key(key, sender)?;
        crate::nip44::decrypt(&conversation, payload)
    }
}

impl FileKeystore {
    /// Derives the NIP-44 conversation key with `peer`.
    ///
    /// Inherent rather than part of [`Signer`], and not public: it returns key
    /// material, which is exactly what a remote or hardware signer exists never
    /// to do. Here it is a local shortcut so `nip44_encrypt` and `nip44_decrypt`
    /// share one derivation; on the trait it would have been a method every
    /// external implementation must refuse.
    fn conversation_key(&self, key: KeyRef, peer: &PublicKey) -> crate::Result<ConversationKey> {
        let derived = self.derived(key.account)?;
        ConversationKey::derive(derived.secret_bytes(), peer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PHRASE: &str =
        "leader monkey parrot ring guide accident before fence cannon height naive bean";

    fn make(dir: &Path) -> (FileKeystore, SecretString) {
        let m = Mnemonic::parse(SecretString::new(PHRASE.to_owned())).expect("parse");
        let pass = SecretString::new("hunter2 hunter2 hunter2".to_owned());
        let ks = FileKeystore::create(
            &dir.join(KEYSTORE_FILENAME),
            &m,
            &pass,
            [1u8; 16],
            [2u8; 24],
            Argon2Params::insecure_for_tests(),
        )
        .expect("create");
        (ks, pass)
    }

    /// The seam M3 stands on: an event signed through the trait must verify
    /// through the same rules a relay applies.
    #[tokio::test]
    async fn a_signed_event_verifies() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (mut ks, pass) = make(dir.path());
        ks.unlock(pass).expect("unlock");

        let key = ks.key_ref(Account::Ghost).expect("key_ref");
        let event = UnsignedEvent {
            pubkey: Signer::public_key(&ks, key).expect("pubkey"),
            created_at: 1_756_252_800,
            // SPEC §9: the Ghostr manifest kind.
            kind: 31780,
            tags: vec![vec!["d".to_owned(), "2026-08-27".to_owned()]],
            content: String::new(),
        };
        let sig = ks.sign_event(key, &event).await.expect("sign");

        let signed = crate::event::SignedEvent {
            id: event.id(),
            event,
            sig,
        };
        signed.verify().expect("verify");
    }

    /// Signing an event that names someone else as its author produces something
    /// no relay will accept, so the signer refuses instead of producing it.
    #[tokio::test]
    async fn signing_under_the_wrong_account_is_refused() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (mut ks, pass) = make(dir.path());
        ks.unlock(pass).expect("unlock");

        let ghost = ks.key_ref(Account::Ghost).expect("key_ref");
        let identity = ks.key_ref(Account::Identity).expect("key_ref");
        let event = UnsignedEvent {
            // Claims the identity account...
            pubkey: Signer::public_key(&ks, identity).expect("pubkey"),
            created_at: 1_756_252_800,
            kind: 31780,
            tags: Vec::new(),
            content: String::new(),
        };

        // ...but is offered to the ghost key.
        assert!(matches!(
            ks.sign_event(ghost, &event).await,
            Err(crate::Error::KeyMismatch)
        ));
    }

    /// Locking is not advisory. Every secret-bearing method must fail closed,
    /// which is the property an idle auto-lock depends on (THREAT_MODEL §T6).
    #[tokio::test]
    async fn a_locked_keystore_signs_nothing() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (mut ks, pass) = make(dir.path());
        ks.unlock(pass).expect("unlock");
        let key = ks.key_ref(Account::Ghost).expect("key_ref");
        let peer = Signer::public_key(&ks, key).expect("pubkey");
        let event = UnsignedEvent {
            pubkey: peer,
            created_at: 1_756_252_800,
            kind: 31780,
            tags: Vec::new(),
            content: String::new(),
        };

        ks.lock();

        assert!(matches!(
            ks.sign_event(key, &event).await,
            Err(crate::Error::Locked)
        ));
        assert!(matches!(
            ks.nip44_encrypt(key, &peer, b"x", [3u8; 32]).await,
            Err(crate::Error::Locked)
        ));
        assert!(matches!(
            ks.conversation_key(key, &peer),
            Err(crate::Error::Locked)
        ));
        assert!(matches!(
            Signer::public_key(&ks, key),
            Err(crate::Error::Locked)
        ));
    }

    /// Self-encryption: the ghost encrypting app data to its own key, which is
    /// how every private Ghostr kind gets its content (SPEC I9).
    #[tokio::test]
    async fn a_payload_round_trips_through_the_signer() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (mut ks, pass) = make(dir.path());
        ks.unlock(pass).expect("unlock");

        let key = ks.key_ref(Account::Ghost).expect("key_ref");
        let own = Signer::public_key(&ks, key).expect("pubkey");
        let payload = ks
            .nip44_encrypt(key, &own, b"footage digest", [42u8; 32])
            .await
            .expect("encrypt");

        assert!(!payload.contains("footage"));
        assert_eq!(
            ks.nip44_decrypt(key, &own, &payload)
                .await
                .expect("decrypt"),
            b"footage digest"
        );
    }

    /// ECDH is symmetric, and NIP-44 relies on it: the recipient derives the
    /// same conversation key from the other side of the pair.
    #[tokio::test]
    async fn the_conversation_key_is_the_same_from_either_side() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (mut ks, pass) = make(dir.path());
        ks.unlock(pass).expect("unlock");

        let ghost = ks.key_ref(Account::Ghost).expect("key_ref");
        let identity = ks.key_ref(Account::Identity).expect("key_ref");
        let ghost_pub = Signer::public_key(&ks, ghost).expect("pubkey");
        let identity_pub = Signer::public_key(&ks, identity).expect("pubkey");

        let forward = ks.conversation_key(ghost, &identity_pub).expect("fwd");
        let backward = ks.conversation_key(identity, &ghost_pub).expect("back");
        assert_eq!(forward.expose(), backward.expose());

        // And a message written by one is readable by the other.
        let payload = ks
            .nip44_encrypt(ghost, &identity_pub, b"hello", [5u8; 32])
            .await
            .expect("encrypt");
        assert_eq!(
            ks.nip44_decrypt(identity, &ghost_pub, &payload)
                .await
                .expect("decrypt"),
            b"hello"
        );
    }

    fn rekey_entropy() -> WrapEntropy {
        WrapEntropy::new([9u8; 16], [8u8; 24], [7u8; 24]).expect("entropy")
    }

    /// The old passphrase stops working and the new one starts.
    #[test]
    fn a_passphrase_change_swaps_which_passphrase_opens_the_vault() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join(KEYSTORE_FILENAME);
        let (mut ks, pass) = make(dir.path());
        ks.unlock(SecretString::new(pass.expose().to_owned()))
            .expect("unlock");

        let new_pass = SecretString::new("an entirely different passphrase".to_owned());
        ks.change_passphrase(
            SecretString::new(pass.expose().to_owned()),
            SecretString::new(new_pass.expose().to_owned()),
            rekey_entropy(),
        )
        .expect("rekey");
        drop(ks);

        let mut reopened = FileKeystore::open(&path).expect("open");
        assert!(
            reopened.unlock(pass).is_err(),
            "the old passphrase still opens the vault"
        );
        let mut again = FileKeystore::open(&path).expect("open");
        again
            .unlock(new_pass)
            .expect("the new passphrase must work");
    }

    /// The corpus stays readable: the DEK does not depend on the passphrase.
    #[test]
    fn a_passphrase_change_leaves_the_data_key_alone() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join(KEYSTORE_FILENAME);
        let (mut ks, pass) = make(dir.path());
        ks.unlock(SecretString::new(pass.expose().to_owned()))
            .expect("unlock");

        // Sealed under the DEK before the change.
        let sealed = crate::kdf::seal_row(ks.dek().expect("dek"), b"a row", &[3u8; 24], b"row:1")
            .expect("seal");

        let new_pass = SecretString::new("an entirely different passphrase".to_owned());
        ks.change_passphrase(
            SecretString::new(pass.expose().to_owned()),
            SecretString::new(new_pass.expose().to_owned()),
            rekey_entropy(),
        )
        .expect("rekey");
        drop(ks);

        let mut reopened = FileKeystore::open(&path).expect("open");
        reopened.unlock(new_pass).expect("unlock");
        assert_eq!(
            crate::kdf::open_row(reopened.dek().expect("dek"), &sealed, &[3u8; 24], b"row:1")
                .expect("the corpus must still decrypt"),
            b"a row"
        );
    }

    /// A wrong old passphrase changes nothing, and says so.
    #[test]
    fn a_wrong_old_passphrase_leaves_the_file_byte_identical() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join(KEYSTORE_FILENAME);
        let (mut ks, pass) = make(dir.path());
        ks.unlock(pass).expect("unlock");

        let before = std::fs::read(&path).expect("read");
        let result = ks.change_passphrase(
            SecretString::new("not the old passphrase".to_owned()),
            SecretString::new("a new one entirely".to_owned()),
            rekey_entropy(),
        );
        assert!(matches!(result, Err(crate::Error::BadPassphrase)));
        assert_eq!(std::fs::read(&path).expect("read"), before);
    }

    /// An imported-identity vault rewraps *both* secrets.
    ///
    /// The failure this guards is asymmetric and silent: rewrapping only the
    /// seed leaves a vault whose journal opens under the new passphrase and
    /// whose identity opens under nothing at all.
    #[test]
    fn a_passphrase_change_rewraps_an_imported_identity_too() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join(KEYSTORE_FILENAME);
        let (mut ks, pass) = imported(dir.path());
        ks.unlock(SecretString::new(pass.expose().to_owned()))
            .expect("unlock");
        let npub_before = ks.npub().as_str().to_owned();

        let new_pass = SecretString::new("an entirely different passphrase".to_owned());
        ks.change_passphrase(
            SecretString::new(pass.expose().to_owned()),
            SecretString::new(new_pass.expose().to_owned()),
            rekey_entropy(),
        )
        .expect("rekey");
        drop(ks);

        // Unlocking is what exercises the imported wrapping: it unwraps the
        // identity key and checks it against the stored pubkey.
        let mut reopened = FileKeystore::open(&path).expect("open");
        reopened
            .unlock(new_pass)
            .expect("the imported identity must survive a rekey");
        assert_eq!(reopened.npub().as_str(), npub_before);
    }

    /// A rekey leaves no temporary file behind.
    #[test]
    fn an_atomic_write_cleans_up_after_itself() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (mut ks, pass) = make(dir.path());
        ks.unlock(SecretString::new(pass.expose().to_owned()))
            .expect("unlock");
        ks.change_passphrase(
            SecretString::new(pass.expose().to_owned()),
            SecretString::new("an entirely different passphrase".to_owned()),
            rekey_entropy(),
        )
        .expect("rekey");

        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .expect("read_dir")
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|name| name.ends_with(".new"))
            .collect();
        assert!(leftovers.is_empty(), "left behind {leftovers:?}");
    }

    /// NIP-19's published `nsec`, with the private key hex it decodes to.
    /// Verbatim from the NIPs repository.
    const NIP19_NSEC: &str = "nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe5";
    const NIP19_NSEC_HEX: &str = "67dea2ed018072d675f5415ecfaed7d2597555e202d85b3d65ea4e58d2d92ffa";

    fn imported(dir: &Path) -> (FileKeystore, SecretString) {
        let secret = crate::nip19::decode_nsec(&SecretString::new(NIP19_NSEC.to_owned()))
            .expect("decode nsec");
        let m = Mnemonic::parse(SecretString::new(PHRASE.to_owned())).expect("parse");
        let pass = SecretString::new("hunter2 hunter2 hunter2".to_owned());
        let entropy = WrapEntropy::new([1u8; 16], [2u8; 24], [3u8; 24]).expect("entropy");
        let ks = FileKeystore::create_with_nsec(
            &dir.join(KEYSTORE_FILENAME),
            secret,
            &m,
            &pass,
            entropy,
            Argon2Params::insecure_for_tests(),
        )
        .expect("create");
        (ks, pass)
    }

    #[test]
    fn the_nip19_nsec_decodes_to_its_documented_key() {
        let secret =
            crate::nip19::decode_nsec(&SecretString::new(NIP19_NSEC.to_owned())).expect("decode");
        assert_eq!(hex::encode(secret.expose()), NIP19_NSEC_HEX);
    }

    #[test]
    fn an_npub_is_not_an_nsec() {
        // Both are bech32 and both are 32 bytes. Only the prefix distinguishes a
        // key you may publish from one you must not.
        let npub = SecretString::new(
            "npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkwsyjh6w6".to_owned(),
        );
        assert!(crate::nip19::decode_nsec(&npub).is_err());
    }

    #[test]
    fn an_imported_identity_is_the_one_the_vault_reports() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (mut ks, pass) = imported(dir.path());

        // Locked, from the file alone.
        assert_eq!(ks.identity_pubkey().expect("pubkey").to_hex().len(), 64);

        ks.unlock(pass).expect("unlock");
        let identity = ks.account_pubkey(Account::Identity).expect("identity");

        // The pubkey the imported secret actually produces, computed
        // independently of the keystore.
        let secret =
            crate::nip19::decode_nsec(&SecretString::new(NIP19_NSEC.to_owned())).expect("decode");
        let expected = crate::nip06::DerivedKey::from_secret(Account::Identity, *secret.expose())
            .expect("derive")
            .public;
        assert_eq!(identity, expected);
    }

    #[test]
    fn an_import_takes_only_the_identity() {
        // Ghost, anchor and data still come from the vault seed — an `nsec` has
        // no tree under it (SPEC Q21). The proof is that they match a
        // seed-derived vault built from the same mnemonic.
        let a = tempfile::tempdir().expect("tempdir");
        let b = tempfile::tempdir().expect("tempdir");
        let (mut plain, p1) = make(a.path());
        let (mut brought, p2) = imported(b.path());
        plain.unlock(p1).expect("unlock");
        brought.unlock(p2).expect("unlock");

        for account in [Account::Ghost, Account::Anchor, Account::Data] {
            assert_eq!(
                plain.account_pubkey(account).expect("pubkey"),
                brought.account_pubkey(account).expect("pubkey"),
                "{account:?} should come from the seed either way"
            );
        }
        // ...and the identity is the one thing that differs.
        assert_ne!(
            plain.account_pubkey(Account::Identity).expect("pubkey"),
            brought.account_pubkey(Account::Identity).expect("pubkey")
        );
    }

    #[test]
    fn an_imported_vault_still_encrypts_and_decrypts() {
        // The point of moving the DEK off the identity key: the vault works
        // regardless of where that key came from.
        let dir = tempfile::tempdir().expect("tempdir");
        let (mut ks, pass) = imported(dir.path());
        ks.unlock(pass).expect("unlock");
        assert!(ks.dek().is_ok());
    }

    #[test]
    fn the_dek_no_longer_depends_on_the_identity_key() {
        // Two vaults, same mnemonic, different identities. If the DEK still came
        // from the identity key these would differ, and importing an `nsec`
        // would make an existing vault unreadable.
        let a = tempfile::tempdir().expect("tempdir");
        let b = tempfile::tempdir().expect("tempdir");
        let (mut plain, p1) = make(a.path());
        let (mut brought, p2) = imported(b.path());
        plain.unlock(p1).expect("unlock");
        brought.unlock(p2).expect("unlock");

        // Compared by behaviour rather than by bytes: `Dek` deliberately has no
        // accessor, and what actually matters is that one vault can read what
        // the other wrote.
        let sealed = crate::kdf::seal_row(
            plain.dek().expect("dek"),
            b"a row written by the seed-derived vault",
            &[7u8; 24],
            b"row:1",
        )
        .expect("seal");
        let opened =
            crate::kdf::open_row(brought.dek().expect("dek"), &sealed, &[7u8; 24], b"row:1")
                .expect("the imported vault should read it");
        assert_eq!(opened, b"a row written by the seed-derived vault");
    }

    #[test]
    fn a_version_one_vault_keeps_its_identity_derived_dek() {
        // The migration promise (CLAUDE.md §4.7). A v1 file has no `dek_source`
        // field; defaulting it to the new scheme would make every existing vault
        // report a wrong passphrase, so absence must mean `Identity`.
        let dir = tempfile::tempdir().expect("tempdir");
        let (ks, pass) = make(dir.path());
        let path = dir.path().join(KEYSTORE_FILENAME);

        // Rewrite the file as a v1 one: drop the fields v1 never had.
        let mut raw: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).expect("read")).expect("parse");
        let object = raw.as_object_mut().expect("object");
        object.insert("version".to_owned(), serde_json::json!(1));
        object.remove("dek_source");
        object.remove("identity_source");
        object.remove("identity_key");
        std::fs::write(&path, serde_json::to_vec(&raw).expect("encode")).expect("write");
        drop(ks);

        let mut reopened = FileKeystore::open(&path).expect("open");
        assert_eq!(reopened.file.dek_source, DekSource::Identity);
        reopened.unlock(pass).expect("a v1 vault still unlocks");

        // And its DEK is the identity-derived one, not the new scheme's —
        // shown by sealing under a DEK derived that way and opening it with the
        // vault's own.
        let identity = reopened.derived(Account::Identity).expect("identity");
        let identity_dek = crate::kdf::derive_dek(identity.secret_bytes());
        let sealed =
            crate::kdf::seal_row(&identity_dek, b"v1 row", &[8u8; 24], b"row:2").expect("seal");
        assert_eq!(
            crate::kdf::open_row(reopened.dek().expect("dek"), &sealed, &[8u8; 24], b"row:2")
                .expect("a v1 vault reads what its identity key sealed"),
            b"v1 row"
        );

        // And *not* the vault-data one, which is the whole point of recording
        // the scheme rather than inferring it.
        let data = reopened.derived(Account::Data).expect("data");
        let data_dek = crate::kdf::derive_dek(data.secret_bytes());
        let other = crate::kdf::seal_row(&data_dek, b"v2 row", &[9u8; 24], b"row:3").expect("seal");
        assert!(
            crate::kdf::open_row(reopened.dek().expect("dek"), &other, &[9u8; 24], b"row:3")
                .is_err()
        );
    }

    #[test]
    fn a_seed_cannot_be_pasted_over_an_imported_identity() {
        // What stops *this* swap is length: a 64-byte seed cannot be read back
        // as a 32-byte key. The AAD separation is the second lock, and it is
        // exercised in `kdf`'s own tests, because nothing at this level wraps
        // two secrets of the same size.
        let dir = tempfile::tempdir().expect("tempdir");
        let (ks, pass) = imported(dir.path());
        let path = dir.path().join(KEYSTORE_FILENAME);
        drop(ks);

        let mut raw: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).expect("read")).expect("parse");
        let seed = raw["seed"].clone();
        raw["identity_key"] = seed;
        std::fs::write(&path, serde_json::to_vec(&raw).expect("encode")).expect("write");

        let mut swapped = FileKeystore::open(&path).expect("open");
        assert!(swapped.unlock(pass).is_err());
    }

    #[test]
    fn a_reused_nonce_cannot_even_be_expressed() {
        // Two secrets under one key must not share a nonce, or they share a
        // keystream. Refused by the constructor rather than by the function that
        // would have used it, so there is no way to hold the bad combination
        // and pass it on.
        assert!(WrapEntropy::new([1u8; 16], [2u8; 24], [2u8; 24]).is_err());
        assert!(WrapEntropy::new([1u8; 16], [2u8; 24], [3u8; 24]).is_ok());
    }

    #[test]
    fn no_key_material_appears_in_an_imported_vaults_file() {
        // I1/I8, for the new wrapping specifically.
        let dir = tempfile::tempdir().expect("tempdir");
        let (_ks, _pass) = imported(dir.path());
        let raw = std::fs::read(dir.path().join(KEYSTORE_FILENAME)).expect("read");
        let text = String::from_utf8_lossy(&raw);
        assert!(!text.contains(NIP19_NSEC));
        assert!(!text.contains(NIP19_NSEC_HEX));
    }

    #[test]
    fn unlock_round_trips_and_derives_the_expected_identity() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (mut ks, pass) = make(dir.path());
        assert!(ks.is_locked());
        ks.unlock(pass).expect("unlock");
        assert!(!ks.is_locked());
        assert_eq!(
            ks.identity_pubkey().expect("pubkey").to_hex(),
            "17162c921dc4d2518f9a101db33695df1afb56ab82f5ff3e5da6eec3ca5cd917"
        );
    }

    #[test]
    fn the_wrong_passphrase_is_rejected() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (mut ks, _) = make(dir.path());
        let err = ks
            .unlock(SecretString::new("wrong".to_owned()))
            .expect_err("must fail");
        assert!(matches!(err, crate::Error::BadPassphrase));
        assert!(ks.is_locked());
    }

    #[test]
    fn locking_makes_the_dek_unavailable() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (mut ks, pass) = make(dir.path());
        ks.unlock(pass).expect("unlock");
        assert!(ks.dek().is_ok());
        ks.lock();
        assert!(matches!(ks.dek(), Err(crate::Error::Locked)));
        assert!(matches!(
            ks.key_ref(Account::Identity),
            Err(crate::Error::Locked)
        ));
    }

    /// The seed must not be recoverable from the file without the passphrase.
    #[test]
    fn no_seed_material_appears_in_the_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (_ks, _) = make(dir.path());
        let raw = std::fs::read_to_string(dir.path().join(KEYSTORE_FILENAME)).expect("read");
        for word in PHRASE.split_whitespace() {
            assert!(
                !raw.contains(word),
                "mnemonic word `{word}` leaked into the keystore"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn the_keystore_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().expect("tempdir");
        let (_ks, _) = make(dir.path());
        let meta = std::fs::metadata(dir.path().join(KEYSTORE_FILENAME)).expect("stat");
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
    }

    #[test]
    fn reopening_preserves_the_recorded_identity() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (ks, _) = make(dir.path());
        let expected = ks.npub();
        let reopened = FileKeystore::open(&dir.path().join(KEYSTORE_FILENAME)).expect("open");
        assert_eq!(reopened.npub(), expected);
        assert!(reopened.is_locked());
    }
}
