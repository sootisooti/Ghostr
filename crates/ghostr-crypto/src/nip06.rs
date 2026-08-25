//! NIP-06: BIP-39 mnemonic, BIP-32 derivation at `m/44'/1237'/<account>'/0/0`.
//!
//! Ghostr derives four accounts from one seed (SPEC §8.1). The separation is the
//! whole point: it lets anchor receipts be published from an account that cannot
//! be linked back to the identity, and it makes a ghost-key compromise a
//! revocation rather than a catastrophe (THREAT_MODEL §T5).

use ghostr_core::identity::{Account, PublicKey};

use crate::secret::{SecretBytes, SecretString};

/// BIP-39 mnemonic word counts Ghostr will accept.
///
/// 12 words is 128 bits of entropy, which is plenty for secp256k1; 24 is offered
/// because users importing an existing seed often have one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum WordCount {
    /// 12 words, 128 bits.
    Twelve,
    /// 24 words, 256 bits.
    TwentyFour,
}

/// A validated BIP-39 mnemonic.
///
/// Zeroized on drop via its inner [`SecretString`]. This is the single most
/// valuable secret in the system: it is not rotatable, and a leak is
/// unrecoverable rather than merely bad (THREAT_MODEL §T5, asset A1).
#[derive(Debug)]
pub struct Mnemonic(SecretString);

impl Mnemonic {
    /// Generates a fresh mnemonic from caller-supplied entropy.
    ///
    /// Entropy is a parameter rather than something read here, so that seed
    /// generation is reproducible in tests. The caller is responsible for it
    /// being cryptographically random — in production that is the composition
    /// root's CSPRNG, and nowhere else.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidMnemonic`](crate::Error::InvalidMnemonic) if the
    /// entropy length does not match `words`.
    pub fn generate(words: WordCount, entropy: &[u8]) -> crate::Result<Self> {
        todo!("map entropy to BIP-39 words and append the checksum")
    }

    /// Parses and validates a mnemonic, checksum included.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidMnemonic`](crate::Error::InvalidMnemonic) if a
    /// word is not in the wordlist, the count is unsupported, or the checksum
    /// fails.
    pub fn parse(phrase: SecretString) -> crate::Result<Self> {
        todo!("normalise, look up each word, verify the checksum")
    }

    /// Borrows the phrase.
    #[must_use]
    pub fn expose(&self) -> &str {
        self.0.expose()
    }

    /// Stretches the mnemonic into a 64-byte BIP-39 seed.
    ///
    /// The optional passphrase is BIP-39's 25th word, which produces an entirely
    /// different seed. Ghostr does not use it by default: a forgotten 25th word
    /// is indistinguishable from a wrong one, and the failure mode is total
    /// silent loss of the identity.
    #[must_use]
    pub fn to_seed(&self, passphrase: Option<&SecretString>) -> SecretBytes<64> {
        todo!("PBKDF2-HMAC-SHA512, 2048 iterations, per BIP-39")
    }
}

/// A BIP-32 master key derived from a seed.
#[derive(Debug)]
pub struct MasterKey {
    _private: (),
}

impl MasterKey {
    /// Derives the master key from a BIP-39 seed.
    #[must_use]
    pub fn from_seed(seed: &SecretBytes<64>) -> Self {
        todo!("HMAC-SHA512 with key 'Bitcoin seed' per BIP-32")
    }

    /// Derives the keypair for one Ghostr account.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidDerivationPath`](crate::Error::InvalidDerivationPath)
    /// if derivation hits an invalid child index, which is astronomically
    /// unlikely and must still not be silently retried.
    pub fn derive_account(&self, account: Account) -> crate::Result<DerivedKey> {
        todo!("derive m/44'/1237'/<account>'/0/0 with hardened path components")
    }
}

/// A derived keypair.
///
/// The secret half is held in zeroizing storage and is never returned. Signing
/// goes through [`Signer`](crate::Signer), which is what makes a hardware or
/// remote signer substitutable.
#[derive(Debug)]
pub struct DerivedKey {
    /// The x-only public key.
    pub public: PublicKey,
    /// Which account this came from.
    pub account: Account,
}

impl DerivedKey {
    /// Signs a 32-byte message with BIP-340 Schnorr.
    ///
    /// Crate-internal: outside this crate, signing is [`Signer`](crate::Signer).
    ///
    /// # Errors
    ///
    /// Returns an error if the secret key is unavailable or the nonce cannot be
    /// generated.
    pub(crate) fn sign(&self, message: &[u8; 32]) -> crate::Result<crate::event::Signature> {
        todo!("BIP-340 Schnorr sign with the derived secret key")
    }
}

/// Verifies a BIP-340 Schnorr signature.
///
/// # Errors
///
/// Returns [`Error::BadSignature`](crate::Error::BadSignature) if the signature
/// does not verify, or
/// [`Error::InvalidPublicKey`](crate::Error::InvalidPublicKey) if the key is not
/// a curve point.
pub fn verify(
    pubkey: &PublicKey,
    message: &[u8; 32],
    sig: &crate::event::Signature,
) -> crate::Result<()> {
    todo!("BIP-340 Schnorr verification")
}
