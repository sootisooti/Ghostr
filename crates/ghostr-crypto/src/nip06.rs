//! NIP-06: BIP-39 mnemonic, BIP-32 derivation at `m/44'/1237'/<account>'/0/0`.
//!
//! Ghostr derives four accounts from one seed (SPEC §8.1). The separation is the
//! whole point: it lets anchor receipts be published from an account that cannot
//! be linked back to the identity, and it makes a ghost-key compromise a
//! revocation rather than a catastrophe (THREAT_MODEL §T5).

use ghostr_core::identity::{Account, PublicKey};
use hmac::{Hmac, Mac};
use secp256k1::{Secp256k1, SecretKey};
use sha2::Sha512;
use zeroize::Zeroizing;

use crate::secret::{SecretBytes, SecretString};

/// NIP-06's coin type. 1237 is nostr's SLIP-44 registration.
const NOSTR_COIN_TYPE: u32 = 1237;

/// BIP-32 hardened-derivation offset.
const HARDENED: u32 = 0x8000_0000;

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

impl WordCount {
    /// Bytes of entropy this word count encodes.
    #[must_use]
    pub const fn entropy_bytes(self) -> usize {
        match self {
            Self::Twelve => 16,
            Self::TwentyFour => 32,
        }
    }
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
        if entropy.len() != words.entropy_bytes() {
            return Err(crate::Error::InvalidMnemonic);
        }
        let m =
            bip39::Mnemonic::from_entropy(entropy).map_err(|_| crate::Error::InvalidMnemonic)?;
        Ok(Self(SecretString::new(m.to_string())))
    }

    /// Parses and validates a mnemonic, checksum included.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidMnemonic`](crate::Error::InvalidMnemonic) if a
    /// word is not in the wordlist, the count is unsupported, or the checksum
    /// fails.
    pub fn parse(phrase: SecretString) -> crate::Result<Self> {
        let normalised = phrase
            .expose()
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        let parsed: bip39::Mnemonic = normalised
            .parse()
            .map_err(|_| crate::Error::InvalidMnemonic)?;
        let count = parsed.word_count();
        if count != 12 && count != 24 {
            return Err(crate::Error::InvalidMnemonic);
        }
        Ok(Self(SecretString::new(normalised)))
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
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidMnemonic`](crate::Error::InvalidMnemonic) if the
    /// stored phrase no longer parses, which cannot happen through the public
    /// constructors.
    pub fn to_seed(&self, passphrase: Option<&SecretString>) -> crate::Result<SecretBytes<64>> {
        let parsed: bip39::Mnemonic = self
            .0
            .expose()
            .parse()
            .map_err(|_| crate::Error::InvalidMnemonic)?;
        let seed = parsed.to_seed(passphrase.map_or("", SecretString::expose));
        Ok(SecretBytes::new(seed))
    }
}

/// A BIP-32 master key derived from a seed.
pub struct MasterKey {
    key: Zeroizing<[u8; 32]>,
    chain_code: Zeroizing<[u8; 32]>,
}

impl core::fmt::Debug for MasterKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("MasterKey(<redacted>)")
    }
}

impl MasterKey {
    /// Derives the master key from a BIP-39 seed.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidDerivationPath`](crate::Error::InvalidDerivationPath)
    /// if HMAC rejects the key length, which cannot happen for a fixed key.
    pub fn from_seed(seed: &SecretBytes<64>) -> crate::Result<Self> {
        let mut mac = Hmac::<Sha512>::new_from_slice(b"Bitcoin seed")
            .map_err(|_| crate::Error::InvalidDerivationPath)?;
        mac.update(seed.expose());
        let out = mac.finalize().into_bytes();
        let mut key = [0u8; 32];
        let mut chain_code = [0u8; 32];
        key.copy_from_slice(&out[..32]);
        chain_code.copy_from_slice(&out[32..]);
        Ok(Self {
            key: Zeroizing::new(key),
            chain_code: Zeroizing::new(chain_code),
        })
    }

    /// Derives the keypair for one Ghostr account.
    ///
    /// Path is `m/44'/1237'/<account>'/0/0`. The first three levels are hardened,
    /// so a leaked child key cannot be walked back up to a sibling account —
    /// which is the property that makes the anchor key genuinely unlinkable from
    /// the identity key.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidDerivationPath`](crate::Error::InvalidDerivationPath)
    /// if derivation hits an invalid child index, which is astronomically
    /// unlikely and must still not be silently retried.
    pub fn derive_account(&self, account: Account) -> crate::Result<DerivedKey> {
        let path = [
            44 | HARDENED,
            NOSTR_COIN_TYPE | HARDENED,
            account.index() | HARDENED,
            0,
            0,
        ];
        let mut key = self.key.clone();
        let mut chain_code = self.chain_code.clone();
        for index in path {
            let (next_key, next_cc) = derive_child(&key, &chain_code, index)?;
            key = next_key;
            chain_code = next_cc;
        }
        let secret =
            SecretKey::from_byte_array(*key).map_err(|_| crate::Error::InvalidDerivationPath)?;
        let secp = Secp256k1::new();
        let (xonly, _parity) = secret.x_only_public_key(&secp);
        Ok(DerivedKey {
            public: PublicKey::from_bytes(xonly.serialize()),
            account,
            secret: SecretBytes::new(secret.secret_bytes()),
        })
    }
}

/// A BIP-32 extended key: the secret scalar plus its chain code.
///
/// Both halves zeroize on drop, which is why this is a pair of `Zeroizing`
/// buffers rather than a plain tuple of arrays.
type ExtendedKey = (Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>);

/// One BIP-32 CKDpriv step.
fn derive_child(
    key: &Zeroizing<[u8; 32]>,
    chain_code: &Zeroizing<[u8; 32]>,
    index: u32,
) -> crate::Result<ExtendedKey> {
    let mut mac = Hmac::<Sha512>::new_from_slice(chain_code.as_slice())
        .map_err(|_| crate::Error::InvalidDerivationPath)?;
    if index >= HARDENED {
        mac.update(&[0u8]);
        mac.update(key.as_slice());
    } else {
        let parent =
            SecretKey::from_byte_array(**key).map_err(|_| crate::Error::InvalidDerivationPath)?;
        let secp = Secp256k1::new();
        mac.update(&parent.public_key(&secp).serialize());
    }
    mac.update(&index.to_be_bytes());
    let out = mac.finalize().into_bytes();

    let parent =
        SecretKey::from_byte_array(**key).map_err(|_| crate::Error::InvalidDerivationPath)?;
    let tweak = secp256k1::Scalar::from_be_bytes(
        out[..32]
            .try_into()
            .map_err(|_| crate::Error::InvalidDerivationPath)?,
    )
    .map_err(|_| crate::Error::InvalidDerivationPath)?;
    let child = parent
        .add_tweak(&tweak)
        .map_err(|_| crate::Error::InvalidDerivationPath)?;

    let mut next_key = [0u8; 32];
    let mut next_cc = [0u8; 32];
    next_key.copy_from_slice(&child.secret_bytes());
    next_cc.copy_from_slice(&out[32..]);
    Ok((Zeroizing::new(next_key), Zeroizing::new(next_cc)))
}

/// A derived keypair.
///
/// The secret half is held in zeroizing storage and is never returned outside
/// this crate. Signing goes through [`Signer`](crate::Signer), which is what
/// makes a hardware or remote signer substitutable.
pub struct DerivedKey {
    /// The x-only public key.
    pub public: PublicKey,
    /// Which account this came from.
    pub account: Account,
    secret: SecretBytes<32>,
}

impl core::fmt::Debug for DerivedKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DerivedKey")
            .field("public", &self.public)
            .field("account", &self.account)
            .finish_non_exhaustive()
    }
}

impl DerivedKey {
    /// Borrows the raw secret key bytes.
    ///
    /// Crate-internal. The store's data key is derived from the identity secret
    /// key (SPEC §10.1), which is the one caller that needs these bytes rather
    /// than a signature.
    pub(crate) fn secret_bytes(&self) -> &[u8; 32] {
        self.secret.expose()
    }

    /// Builds a key from raw secret bytes.
    ///
    /// Crate-internal, and the only caller is an imported `nsec` (SPEC §14 Q21):
    /// a raw nostr key has no BIP-32 tree under it, so there is nothing to
    /// derive it *from* and it has to be adopted as-is.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidPublicKey`](crate::Error::InvalidPublicKey) if
    /// the bytes are not a valid secp256k1 scalar — zero, or above the curve
    /// order. Checked here rather than at first use, so an unusable key is
    /// refused at import instead of at the first signature.
    pub(crate) fn from_secret(account: Account, secret: [u8; 32]) -> crate::Result<Self> {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_byte_array(secret).map_err(|_| crate::Error::InvalidPublicKey)?;
        let (x_only, _parity) = sk.x_only_public_key(&secp);
        Ok(Self {
            public: PublicKey::from_bytes(x_only.serialize()),
            account,
            secret: SecretBytes::new(secret),
        })
    }

    /// Signs a 32-byte message with BIP-340 Schnorr.
    ///
    /// Crate-internal: outside this crate, signing is [`Signer`](crate::Signer).
    ///
    /// # Errors
    ///
    /// Returns an error if the secret key is unavailable.
    pub(crate) fn sign(&self, message: &[u8; 32]) -> crate::Result<crate::event::Signature> {
        let secp = Secp256k1::new();
        let keypair = secp256k1::Keypair::from_seckey_byte_array(&secp, *self.secret.expose())
            .map_err(|_| crate::Error::BadSignature)?;
        let sig = secp.sign_schnorr_no_aux_rand(message, &keypair);
        Ok(crate::event::Signature::from_bytes(*sig.as_ref()))
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
    let secp = Secp256k1::new();
    let xonly = secp256k1::XOnlyPublicKey::from_byte_array(*pubkey.as_bytes())
        .map_err(|_| crate::Error::InvalidPublicKey)?;
    let signature = secp256k1::schnorr::Signature::from_byte_array(*sig.as_bytes());
    secp.verify_schnorr(&signature, message, &xonly)
        .map_err(|_| crate::Error::BadSignature)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// NIP-06 test vector, taken verbatim from the NIPs repository.
    ///
    /// Copied unmodified on purpose (CLAUDE.md §6): a vector adjusted to match
    /// our output is not a test, it is a transcription of a bug.
    const NIP06_MNEMONIC: &str =
        "leader monkey parrot ring guide accident before fence cannon height naive bean";
    const NIP06_EXPECTED_PUBKEY: &str =
        "17162c921dc4d2518f9a101db33695df1afb56ab82f5ff3e5da6eec3ca5cd917";

    #[test]
    fn nip06_vector_derives_the_documented_key() {
        let m = Mnemonic::parse(SecretString::new(NIP06_MNEMONIC.to_owned())).expect("parse");
        let seed = m.to_seed(None).expect("seed");
        let master = MasterKey::from_seed(&seed).expect("master");
        let key = master.derive_account(Account::Identity).expect("derive");
        assert_eq!(key.public.to_hex(), NIP06_EXPECTED_PUBKEY);
    }

    #[test]
    fn accounts_derive_distinct_keys() {
        let m = Mnemonic::parse(SecretString::new(NIP06_MNEMONIC.to_owned())).expect("parse");
        let seed = m.to_seed(None).expect("seed");
        let master = MasterKey::from_seed(&seed).expect("master");
        let keys: Vec<_> = [
            Account::Identity,
            Account::Ghost,
            Account::Anchor,
            Account::Data,
        ]
        .into_iter()
        .map(|a| master.derive_account(a).expect("derive").public.to_hex())
        .collect();
        let unique: std::collections::HashSet<_> = keys.iter().collect();
        assert_eq!(
            unique.len(),
            4,
            "account separation must yield distinct keys"
        );
    }

    #[test]
    fn derivation_is_deterministic() {
        let m = Mnemonic::parse(SecretString::new(NIP06_MNEMONIC.to_owned())).expect("parse");
        let a = MasterKey::from_seed(&m.to_seed(None).expect("seed"))
            .expect("master")
            .derive_account(Account::Identity)
            .expect("derive");
        let b = MasterKey::from_seed(&m.to_seed(None).expect("seed"))
            .expect("master")
            .derive_account(Account::Identity)
            .expect("derive");
        assert_eq!(a.public, b.public);
        assert_eq!(a.secret_bytes(), b.secret_bytes());
    }

    #[test]
    fn a_bad_checksum_is_rejected() {
        // Last word swapped: the wordlist accepts it, the checksum does not.
        let bad = NIP06_MNEMONIC.replace("bean", "zoo");
        assert!(Mnemonic::parse(SecretString::new(bad)).is_err());
    }

    #[test]
    fn generate_requires_matching_entropy_length() {
        assert!(Mnemonic::generate(WordCount::Twelve, &[0u8; 16]).is_ok());
        assert!(Mnemonic::generate(WordCount::Twelve, &[0u8; 32]).is_err());
        assert!(Mnemonic::generate(WordCount::TwentyFour, &[0u8; 32]).is_ok());
    }

    #[test]
    fn signatures_verify_and_reject_tampering() {
        let m = Mnemonic::parse(SecretString::new(NIP06_MNEMONIC.to_owned())).expect("parse");
        let key = MasterKey::from_seed(&m.to_seed(None).expect("seed"))
            .expect("master")
            .derive_account(Account::Identity)
            .expect("derive");
        let msg = [42u8; 32];
        let sig = key.sign(&msg).expect("sign");
        assert!(verify(&key.public, &msg, &sig).is_ok());

        let mut other = msg;
        other[0] ^= 1;
        assert!(verify(&key.public, &other, &sig).is_err());
    }
}
