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
use crate::kdf::{Argon2Params, Dek, WrappedSeed, derive_dek, derive_kek, unwrap_seed, wrap_seed};
use crate::nip06::{DerivedKey, MasterKey, Mnemonic};
use crate::nip44::ConversationKey;
use crate::secret::SecretString;
use crate::signer::{Keystore, Signer};

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
}

/// The current keystore format version.
pub const KEYSTORE_VERSION: u32 = 1;

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
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut f = options.open(path).map_err(|_| crate::Error::Backend {
        operation: "open keystore for writing",
    })?;
    f.write_all(bytes).map_err(|_| crate::Error::Backend {
        operation: "write keystore",
    })?;
    f.sync_all().map_err(|_| crate::Error::Backend {
        operation: "sync keystore",
    })?;
    Ok(())
}

impl Keystore for FileKeystore {
    fn unlock(&mut self, passphrase: SecretString) -> crate::Result<()> {
        let kek = derive_kek(&passphrase, &self.file.seed.salt, self.file.seed.params)?;
        let seed = unwrap_seed(&kek, &self.file.seed)?;
        let master = MasterKey::from_seed(&seed)?;

        let keys = [
            Account::Identity,
            Account::Ghost,
            Account::Anchor,
            Account::Data,
        ]
        .into_iter()
        .map(|a| master.derive_account(a))
        .collect::<crate::Result<Vec<_>>>()?;

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

        let dek = derive_dek(identity.secret_bytes());
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

    fn change_passphrase(&mut self, new_passphrase: SecretString) -> crate::Result<()> {
        // Not implementable at this signature, and refused rather than faked.
        // A rewrap needs a fresh salt and nonce; drawing them here would put
        // `OsRng` outside the composition root, which CLAUDE.md §6 forbids, and
        // reusing the stored salt would wrap a new KEK under an old one's
        // parameters. Resolving that means changing the trait — SPEC §14 Q19.
        let _ = new_passphrase;
        Err(crate::Error::Backend {
            operation: "change_passphrase needs a caller-supplied salt",
        })
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
        let conversation = self.conversation_key(key, recipient).await?;
        crate::nip44::encrypt(&conversation, plaintext, &nonce)
    }

    async fn nip44_decrypt(
        &self,
        key: KeyRef,
        sender: &PublicKey,
        payload: &str,
    ) -> crate::Result<Vec<u8>> {
        let conversation = self.conversation_key(key, sender).await?;
        crate::nip44::decrypt(&conversation, payload)
    }

    async fn conversation_key(
        &self,
        key: KeyRef,
        peer: &PublicKey,
    ) -> crate::Result<ConversationKey> {
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
            ks.conversation_key(key, &peer).await,
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

        let forward = ks
            .conversation_key(ghost, &identity_pub)
            .await
            .expect("fwd");
        let backward = ks
            .conversation_key(identity, &ghost_pub)
            .await
            .expect("back");
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

    /// The stub is honest about being a stub, and says why (SPEC §14 Q19).
    #[test]
    fn change_passphrase_refuses_rather_than_rewrapping_badly() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (mut ks, pass) = make(dir.path());
        ks.unlock(pass).expect("unlock");

        let before = std::fs::read(dir.path().join(KEYSTORE_FILENAME)).expect("read");
        assert!(
            ks.change_passphrase(SecretString::new("a new one entirely".to_owned()))
                .is_err()
        );
        // Refusing must not have half-written the file.
        assert_eq!(
            std::fs::read(dir.path().join(KEYSTORE_FILENAME)).expect("read"),
            before
        );
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
