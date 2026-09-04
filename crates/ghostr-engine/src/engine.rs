//! The engine: everything wired together.
//!
//! Holds no domain logic. It decides *when* things run and *which*
//! implementations run; never *what* they mean. Rules about extraction,
//! summarisation, or the chain live in the crates that own them.

use std::path::{Path, PathBuf};

use chrono::NaiveDate;
use chrono_tz::Tz;
use ghostr_core::hash::Hash32;
use ghostr_core::identity::{Account, Npub};
use ghostr_core::ids::ChainId;
use ghostr_core::time::{Clock, Rng, Timestamp};
use ghostr_crypto::kdf::Argon2Params;
use ghostr_crypto::keystore::{FileKeystore, KEYSTORE_FILENAME};
use ghostr_crypto::nip06::{Mnemonic, WordCount};
use ghostr_crypto::secret::SecretString;
use ghostr_crypto::signer::Keystore as _;
use ghostr_store::SqliteStore;

use crate::runtime::{OsRng, SystemClock};

/// Everything wired together for M0.
///
/// Constructed once per command. The clock and RNG are trait objects so an
/// integration test can drive the whole flow deterministically.
pub struct Engine {
    dir: PathBuf,
    keystore: FileKeystore,
    store: SqliteStore,
    clock: Box<dyn Clock>,
    rng: Box<dyn Rng>,
}

impl core::fmt::Debug for Engine {
    /// Prints location and lock state, never key material or content.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Engine")
            .field("dir", &self.dir)
            .field("locked", &self.keystore.is_locked())
            .finish()
    }
}

/// Whether a device may advance the chain.
///
/// Not a capability the software grants itself: handover is a decision a person
/// makes, because an automatic election plus a network partition is a fork
/// (SPEC §14 Q10).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DeviceRole {
    /// Runs Memoria and advances `seq`. Exactly one per chain.
    Sealer,
    /// Ingests, answers quests, and reads. Never seals.
    Replica,
}

/// What `init` produced.
#[derive(Debug)]
pub struct InitOutcome {
    /// The identity npub.
    pub npub: Npub,
    /// The generated mnemonic, if one was generated rather than imported.
    ///
    /// Returned exactly once, at creation, and never persisted in plaintext.
    /// The caller shows it and forgets it.
    pub mnemonic: Option<String>,
    /// The genesis link this chain starts from.
    pub genesis_link: Hash32,
    /// Whether the identity key was brought by the user rather than derived.
    ///
    /// Changes what the recovery phrase *is*, and therefore what the user has to
    /// be told. On a normal vault the phrase is the whole identity; on an
    /// imported one it is only the vault seed, and the `nsec` is the other half
    /// (SPEC §14 Q21). Telling someone with two secrets that they have one is
    /// how a key gets lost.
    pub identity_imported: bool,
}

impl Engine {
    /// Creates a new identity, keystore, and store.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Config`](crate::Error::Config) if a keystore already
    /// exists — refusing rather than overwriting, because overwriting a keystore
    /// destroys an identity that cannot be regenerated.
    pub fn init(
        dir: &Path,
        passphrase: &SecretString,
        home_tz: Tz,
        import: Option<SecretString>,
        nsec: Option<SecretString>,
        params: Argon2Params,
    ) -> crate::Result<(Self, InitOutcome)> {
        let keystore_path = dir.join(KEYSTORE_FILENAME);
        if FileKeystore::exists(&keystore_path) {
            return Err(crate::Error::Config {
                detail: format!("a keystore already exists at {}", keystore_path.display()),
            });
        }

        let clock = SystemClock::new(home_tz);
        let rng = OsRng;

        let (mnemonic, revealed) = match import {
            Some(phrase) => (Mnemonic::parse(phrase)?, None),
            None => {
                let mut entropy = [0u8; 16];
                rng.fill(&mut entropy);
                let m = Mnemonic::generate(WordCount::Twelve, &entropy)?;
                let phrase = m.expose().to_owned();
                (m, Some(phrase))
            }
        };

        let mut salt = [0u8; 16];
        let mut nonce = [0u8; 24];
        rng.fill(&mut salt);
        rng.fill(&mut nonce);

        let imported_identity = nsec.is_some();
        let mut keystore = match nsec {
            // The imported key becomes the identity; the vault seed still
            // produces ghost, anchor and data, and the DEK (SPEC §14 Q21).
            Some(encoded) => {
                let secret = ghostr_crypto::nip19::decode_nsec(&encoded)?;
                let mut identity_nonce = [0u8; 24];
                rng.fill(&mut identity_nonce);
                let entropy =
                    ghostr_crypto::keystore::WrapEntropy::new(salt, nonce, identity_nonce)?;
                FileKeystore::create_with_nsec(
                    &keystore_path,
                    secret,
                    &mnemonic,
                    passphrase,
                    entropy,
                    params,
                )?
            }
            None => {
                FileKeystore::create(&keystore_path, &mnemonic, passphrase, salt, nonce, params)?
            }
        };
        keystore.unlock(SecretString::new(passphrase.expose().to_owned()))?;

        let identity = keystore.identity_pubkey()?;
        let npub = keystore.npub();

        let now = clock.now();
        let mut chain_random = [0u8; 10];
        rng.fill(&mut chain_random);
        let chain_id = ChainId::new(now.utc_millis().unsigned_abs(), chain_random);
        let genesis_link = ghostr_anchor::genesis(&identity, chain_id, now);

        let store = SqliteStore::open(dir)?;
        store.init_chain(chain_id, &identity, genesis_link, home_tz, now)?;

        Ok((
            Self {
                dir: dir.to_path_buf(),
                keystore,
                store,
                clock: Box::new(clock),
                rng: Box::new(rng),
            },
            InitOutcome {
                npub,
                mnemonic: revealed,
                genesis_link,
                identity_imported: imported_identity,
            },
        ))
    }

    /// The vault's configuration, loaded from disk.
    ///
    /// Read rather than cached, like every other config consumer here: a
    /// long-running `serve` should pick up an edit without a restart, and the
    /// file is small.
    ///
    /// # Errors
    ///
    /// Returns an error if the file exists but does not parse.
    pub fn config(&self) -> crate::Result<crate::config::Config> {
        crate::config::Config::load(&self.dir)
    }

    /// Whether this device may seal, or is a read replica.
    ///
    /// # Why this exists at all
    ///
    /// Two devices sealing the same `seq` forks the chain, and a forked chain
    /// is worthless — there is no rule that says which side is real. Exactly one
    /// device per chain seals; every other one ingests, answers quests and
    /// reads (SPEC §14 Q10).
    ///
    /// A vault that has never been told otherwise is a sealer: that is what
    /// `init` produces, and it keeps a single-device user from having to know
    /// this concept exists.
    ///
    /// # Errors
    ///
    /// Returns an error if the store cannot be read.
    pub fn device_role(&self) -> crate::Result<DeviceRole> {
        Ok(
            match self
                .store
                .meta(ghostr_store::schema::meta_key::DEVICE_ROLE)?
            {
                Some(value) if value == "replica" => DeviceRole::Replica,
                _ => DeviceRole::Sealer,
            },
        )
    }

    /// Records this device's role.
    ///
    /// # Errors
    ///
    /// Returns an error if the store cannot be written.
    pub fn set_device_role(&self, role: DeviceRole) -> crate::Result<()> {
        self.store.set_meta(
            ghostr_store::schema::meta_key::DEVICE_ROLE,
            match role {
                DeviceRole::Sealer => "sealer",
                DeviceRole::Replica => "replica",
            },
        )?;
        Ok(())
    }

    /// Changes the passphrase that unlocks this vault.
    ///
    /// Entropy is drawn here rather than in `ghostr-crypto`: this is the
    /// composition root, which is the only place `OsRng` belongs (§11.4).
    ///
    /// # Errors
    ///
    /// Returns an error if `old` is wrong or the new wrapping cannot be
    /// written. The stored file is left unchanged on either.
    pub fn change_passphrase(
        &mut self,
        old: SecretString,
        new: SecretString,
        entropy: ghostr_crypto::keystore::WrapEntropy,
    ) -> crate::Result<()> {
        Ok(self.keystore.change_passphrase(old, new, entropy)?)
    }

    /// Opens an existing vault and unlocks it.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Config`](crate::Error::Config) if no vault exists, or a
    /// crypto error if the passphrase is wrong.
    pub fn open(dir: &Path, passphrase: &SecretString) -> crate::Result<Self> {
        Self::open_with(dir, passphrase, None, None)
    }

    /// Opens a vault with explicit clock and RNG.
    ///
    /// The seam integration tests use: a fixed clock and a seeded RNG make the
    /// whole flow reproducible, including salts, nonces, and identifiers.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Config`](crate::Error::Config) if no vault exists.
    pub fn open_with(
        dir: &Path,
        passphrase: &SecretString,
        clock: Option<Box<dyn Clock>>,
        rng: Option<Box<dyn Rng>>,
    ) -> crate::Result<Self> {
        let keystore_path = dir.join(KEYSTORE_FILENAME);
        if !FileKeystore::exists(&keystore_path) {
            return Err(crate::Error::Config {
                detail: format!("no vault at {} — run `ghostr init` first", dir.display()),
            });
        }
        let mut keystore = FileKeystore::open(&keystore_path)?;
        keystore.unlock(SecretString::new(passphrase.expose().to_owned()))?;
        let store = SqliteStore::open(dir)?;
        let home_tz = store.home_tz()?;

        Ok(Self {
            dir: dir.to_path_buf(),
            keystore,
            store,
            clock: clock.unwrap_or_else(|| Box::new(SystemClock::new(home_tz))),
            rng: rng.unwrap_or_else(|| Box::new(OsRng)),
        })
    }

    /// The data directory.
    #[must_use]
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// The store.
    #[must_use]
    pub fn store(&self) -> &SqliteStore {
        &self.store
    }

    /// The keystore.
    #[must_use]
    pub fn keystore(&self) -> &FileKeystore {
        &self.keystore
    }

    /// The clock.
    #[must_use]
    pub fn clock(&self) -> &dyn Clock {
        self.clock.as_ref()
    }

    /// The RNG.
    #[must_use]
    pub fn rng(&self) -> &dyn Rng {
        self.rng.as_ref()
    }

    /// The identity npub.
    #[must_use]
    pub fn npub(&self) -> Npub {
        self.keystore.npub()
    }

    /// The home timezone this chain seals in.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Store`](crate::Error::Store) if it is missing.
    pub fn home_tz(&self) -> crate::Result<Tz> {
        Ok(self.store.home_tz()?)
    }

    /// Resolves `today`, `yesterday`, or a `YYYY-MM-DD` string to a date.
    ///
    /// Parsed against the *home* zone rather than the ambient one, so "today"
    /// means the same day the cutoff will seal (SPEC Q11).
    ///
    /// # Errors
    ///
    /// Returns [`Error::Config`](crate::Error::Config) if the string is not a
    /// date this understands.
    pub fn resolve_date(&self, spec: &str) -> crate::Result<NaiveDate> {
        let tz = self.home_tz()?;
        let today = self.clock.now().date_in(&tz);
        match spec.trim().to_lowercase().as_str() {
            "today" => Ok(today),
            "yesterday" => today.pred_opt().ok_or_else(|| crate::Error::Config {
                detail: "date underflow".to_owned(),
            }),
            other => other
                .parse::<NaiveDate>()
                .map_err(|_| crate::Error::Config {
                    detail: format!(
                        "`{other}` is not a date; try `today`, `yesterday`, or YYYY-MM-DD"
                    ),
                }),
        }
    }

    /// A fresh 24-byte AEAD nonce.
    ///
    /// Every sealed row gets its own. Reusing a nonce under one key is the
    /// classic way to lose confidentiality in a stream cipher, so this is the
    /// only way rows get one.
    pub fn nonce(&self) -> [u8; 24] {
        let mut out = [0u8; 24];
        self.rng.fill(&mut out);
        out
    }

    /// Borrows the data encryption key.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Locked`](crate::Error::Locked) if the keystore is locked.
    pub fn dek(&self) -> crate::Result<&ghostr_crypto::kdf::Dek> {
        self.keystore.dek().map_err(|_| crate::Error::Locked)
    }

    /// The identity account's key reference.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Locked`](crate::Error::Locked) if locked.
    pub fn identity_key(&self) -> crate::Result<ghostr_core::identity::KeyRef> {
        Ok(self.keystore.key_ref(Account::Identity)?)
    }

    /// A timestamp for now.
    #[must_use]
    pub fn now(&self) -> Timestamp {
        self.clock.now()
    }
}
