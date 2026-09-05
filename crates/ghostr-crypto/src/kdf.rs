//! Passphrase stretching and the at-rest key hierarchy (SPEC §10.1).
//!
//! ```text
//! passphrase --Argon2id--> KEK --unwraps--> seed --NIP-06--> identity secret key
//!  (m=256MiB, t=3, p=4)                                              |
//!                                    HKDF-SHA256(ikm = sk, info = label)
//!                                                                    |
//!                                                                   DEK
//!                                                                    |
//!                                       XChaCha20-Poly1305 --> database + blobs
//! ```
//!
//! Three decisions worth stating plainly:
//!
//! - **The DEK is derived from the identity secret key, not stored.** So the
//!   store is readable only by someone who can reach the nostr key, and there is
//!   no second secret to back up, lose, or leak. Nothing on disk holds the DEK.
//! - **The seed is wrapped, not the DEK.** Changing a passphrase rewraps 64
//!   bytes; the DEK is unchanged because the key it derives from is unchanged,
//!   so the corpus is never re-encrypted.
//! - **Argon2id at 256 MiB.** Memory-hardness turns a stolen database from a
//!   GPU-farm problem into a per-device one. It also means unlocking costs a
//!   real fraction of a second and allocates a quarter gigabyte, which is a
//!   deliberate trade rather than an oversight (THREAT_MODEL §T1).

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::secret::{SecretBytes, SecretPage, SecretString};

/// Domain separation for the store's data key.
///
/// Frozen: changing it makes every existing database undecryptable, because the
/// DEK is derived rather than stored and there is no copy to fall back on.
const DEK_INFO: &[u8] = b"ghostr/v1/store-dek";

/// AAD for a wrapped imported identity key.
///
/// Distinct from [`DEK_INFO`] on purpose. Both wrappings sit in the same file
/// under the same KEK, and today a swap between them already fails on length —
/// a seed is 64 bytes and an identity key is 32. The AAD is the lock that keeps
/// that true the day something else 32 bytes long gets wrapped here, when length
/// stops distinguishing them and nothing else would.
///
/// `wrapping_roles_do_not_cross_open` is what holds this to account; without it
/// the constant could be changed to [`DEK_INFO`] and every test would still
/// pass.
const IDENTITY_INFO: &[u8] = b"ghostr/v1/imported-identity";

/// Argon2id parameters. Stored alongside the wrapped seed so that raising the
/// cost later does not strand existing vaults.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Argon2Params {
    /// Memory cost in KiB.
    pub memory_kib: u32,
    /// Time cost, in passes.
    pub iterations: u32,
    /// Parallelism.
    pub lanes: u32,
}

impl Argon2Params {
    /// The current defaults: m=256 MiB, t=3, p=4.
    #[must_use]
    pub const fn recommended() -> Self {
        Self {
            memory_kib: 256 * 1024,
            iterations: 3,
            lanes: 4,
        }
    }

    /// Reduced parameters for tests only.
    ///
    /// `#[cfg(test)]`-gated on purpose. A "fast mode" reachable from production
    /// configuration is a downgrade attack waiting to be discovered.
    #[cfg(test)]
    #[must_use]
    pub const fn insecure_for_tests() -> Self {
        Self {
            memory_kib: 8,
            iterations: 1,
            lanes: 1,
        }
    }

    fn to_argon2(self) -> crate::Result<argon2::Argon2<'static>> {
        let params = argon2::Params::new(self.memory_kib, self.iterations, self.lanes, Some(32))
            .map_err(|_| crate::Error::Backend {
                operation: "argon2 parameters",
            })?;
        Ok(argon2::Argon2::new(
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            params,
        ))
    }
}

/// The key encryption key, derived from the passphrase. Wraps the seed.
///
/// Held in a [`SecretPage`] rather than plain [`SecretBytes`]: THREAT_MODEL §T1
/// and SPEC §8 both name the KEK as `mlock`ed, and it is long-lived — it exists
/// for as long as the vault is unlocked, which is exactly the window in which a
/// page can be swapped out.
pub struct Kek(SecretPage<32>);

impl core::fmt::Debug for Kek {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Kek(<redacted>)")
    }
}

/// The data encryption key, which actually encrypts the corpus.
///
/// Derived from the identity secret key, never persisted.
///
/// Held in a [`SecretPage`] for the same reason as the KEK, and with more at
/// stake: this is the key the whole corpus is encrypted under, and it is in
/// memory for the entire life of an unlocked vault.
pub struct Dek(SecretPage<32>);

impl Dek {
    /// Whether the DEK's page is actually pinned out of swap.
    ///
    /// Reported rather than assumed: `RLIMIT_MEMLOCK` can refuse, and the whole
    /// point of surfacing it is that a silent failure of THREAT_MODEL §T1's
    /// promise would look exactly like success.
    #[must_use]
    pub const fn is_pinned(&self) -> bool {
        self.0.is_locked()
    }
}

impl core::fmt::Debug for Dek {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Dek(<redacted>)")
    }
}

/// A BIP-39 seed encrypted under a KEK, as persisted.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct WrappedSeed {
    /// The wrapped seed bytes, with the AEAD tag appended.
    #[serde(with = "hex_bytes")]
    pub ciphertext: Vec<u8>,
    /// The AEAD nonce.
    #[serde(with = "hex_bytes")]
    pub nonce: Vec<u8>,
    /// The salt the KEK was derived with.
    #[serde(with = "hex_bytes")]
    pub salt: Vec<u8>,
    /// The parameters in force when this was wrapped.
    pub params: Argon2Params,
}

/// Hex encoding for byte vectors in the keystore file, so it stays greppable and
/// diffable rather than being a wall of JSON integer arrays.
mod hex_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    pub(super) fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(v))
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        use serde::de::Error as _;
        hex::decode(String::deserialize(d)?).map_err(D::Error::custom)
    }
}

/// Derives a KEK from a passphrase.
///
/// # Errors
///
/// Returns [`Error::Backend`](crate::Error::Backend) if the Argon2id parameters
/// are invalid or memory cannot be allocated. On a memory-constrained device
/// that is a real, reportable condition rather than a reason to silently weaken
/// the parameters.
pub fn derive_kek(
    passphrase: &SecretString,
    salt: &[u8],
    params: Argon2Params,
) -> crate::Result<Kek> {
    let argon = params.to_argon2()?;
    let mut out = Zeroizing::new([0u8; 32]);
    argon
        .hash_password_into(passphrase.expose().as_bytes(), salt, out.as_mut_slice())
        .map_err(|_| crate::Error::Backend {
            operation: "argon2 derivation",
        })?;
    // A mutable local so the copy this function made is wiped too, rather
    // than lingering on the stack beside the locked page that replaced it.
    let mut raw = *out;
    Ok(Kek(SecretPage::new(&mut raw)))
}

/// Wraps a BIP-39 seed under a KEK.
///
/// # Errors
///
/// Returns [`Error::Backend`](crate::Error::Backend) if encryption fails.
pub fn wrap_seed(
    kek: &Kek,
    seed: &SecretBytes<64>,
    nonce: &[u8; 24],
    salt: &[u8; 16],
    params: Argon2Params,
) -> crate::Result<WrappedSeed> {
    let cipher = XChaCha20Poly1305::new(kek.0.expose().into());
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: seed.expose(),
                aad: DEK_INFO,
            },
        )
        .map_err(|_| crate::Error::Backend {
            operation: "seed wrap",
        })?;
    Ok(WrappedSeed {
        ciphertext,
        nonce: nonce.to_vec(),
        salt: salt.to_vec(),
        params,
    })
}

/// Unwraps a BIP-39 seed.
///
/// # Errors
///
/// Returns [`Error::BadPassphrase`](crate::Error::BadPassphrase) if the KEK does
/// not authenticate the wrapped seed. The AEAD tag failing *is* the
/// wrong-password signal — there is no separate verifier to check first, and no
/// way to distinguish a wrong passphrase from a corrupted file.
pub fn unwrap_seed(kek: &Kek, wrapped: &WrappedSeed) -> crate::Result<SecretBytes<64>> {
    let cipher = XChaCha20Poly1305::new(kek.0.expose().into());
    let plaintext = cipher
        .decrypt(
            XNonce::from_slice(&wrapped.nonce),
            Payload {
                msg: &wrapped.ciphertext,
                aad: DEK_INFO,
            },
        )
        .map_err(|_| crate::Error::BadPassphrase)?;
    let bytes: [u8; 64] = plaintext
        .try_into()
        .map_err(|_| crate::Error::BadPassphrase)?;
    Ok(SecretBytes::new(bytes))
}

/// Wraps an imported 32-byte identity key under a KEK.
///
/// Separate from [`wrap_seed`] because the two are different sizes and, more to
/// the point, different roles: each wrapping is bound to its own AAD, so one
/// cannot be opened as the other.
///
/// # Errors
///
/// Returns [`Error::Backend`](crate::Error::Backend) if encryption fails.
pub fn wrap_identity(
    kek: &Kek,
    key: &SecretBytes<32>,
    nonce: &[u8; 24],
    salt: &[u8; 16],
    params: Argon2Params,
) -> crate::Result<WrappedSeed> {
    let cipher = XChaCha20Poly1305::new(kek.0.expose().into());
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: key.expose(),
                aad: IDENTITY_INFO,
            },
        )
        .map_err(|_| crate::Error::Backend {
            operation: "identity wrap",
        })?;
    Ok(WrappedSeed {
        ciphertext,
        nonce: nonce.to_vec(),
        salt: salt.to_vec(),
        params,
    })
}

/// Unwraps an imported identity key.
///
/// # Errors
///
/// Returns [`Error::BadPassphrase`](crate::Error::BadPassphrase) if the KEK does
/// not authenticate it — which is also what a seed pasted in here produces,
/// because the AAD does not match.
pub fn unwrap_identity(kek: &Kek, wrapped: &WrappedSeed) -> crate::Result<SecretBytes<32>> {
    let cipher = XChaCha20Poly1305::new(kek.0.expose().into());
    let plaintext = cipher
        .decrypt(
            XNonce::from_slice(&wrapped.nonce),
            Payload {
                msg: &wrapped.ciphertext,
                aad: IDENTITY_INFO,
            },
        )
        .map_err(|_| crate::Error::BadPassphrase)?;
    let bytes: [u8; 32] = plaintext
        .try_into()
        .map_err(|_| crate::Error::BadPassphrase)?;
    Ok(SecretBytes::new(bytes))
}

/// Derives the store's data key from the identity secret key.
///
/// This is the step that makes the store readable only to whoever holds the
/// nostr key. HKDF-SHA256 with a fixed `info` label and no salt: the input
/// keying material is already a uniformly random 32-byte secret, so a salt buys
/// nothing, and keeping the derivation a pure function of the secret key means
/// the DEK never has to be stored, backed up, or rotated separately.
#[must_use]
pub fn derive_dek(identity_secret: &[u8; 32]) -> Dek {
    let hk = Hkdf::<Sha256>::new(None, identity_secret);
    let mut out = Zeroizing::new([0u8; 32]);
    // `expand` fails only when the output length exceeds 255 * HashLen; 32 bytes
    // cannot reach that, so the fallback branch is unreachable in practice.
    if hk.expand(DEK_INFO, out.as_mut_slice()).is_err() {
        return Dek(SecretPage::new(&mut [0u8; 32]));
    }
    let mut raw = *out;
    Dek(SecretPage::new(&mut raw))
}

/// Encrypts a row payload under the DEK.
///
/// `aad` binds the ciphertext to its row (`row_type || row_id`), so a row
/// swapped inside the database fails to decrypt rather than silently returning
/// another record's content (SPEC §10.2).
///
/// # Errors
///
/// Returns [`Error::Backend`](crate::Error::Backend) if encryption fails.
pub fn seal_row(
    dek: &Dek,
    plaintext: &[u8],
    nonce: &[u8; 24],
    aad: &[u8],
) -> crate::Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(dek.0.expose().into());
    cipher
        .encrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| crate::Error::Backend {
            operation: "row seal",
        })
}

/// Decrypts a row payload.
///
/// # Errors
///
/// Returns [`Error::DecryptFailed`](crate::Error::DecryptFailed) if the tag does
/// not verify, which includes the case of a row moved to a different id.
pub fn open_row(
    dek: &Dek,
    ciphertext: &[u8],
    nonce: &[u8; 24],
    aad: &[u8],
) -> crate::Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(dek.0.expose().into());
    cipher
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| crate::Error::DecryptFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kek() -> Kek {
        derive_kek(
            &SecretString::new("correct horse battery staple".to_owned()),
            &[9u8; 16],
            Argon2Params::insecure_for_tests(),
        )
        .expect("derive")
    }

    #[test]
    fn seed_wrap_round_trips() {
        let seed = SecretBytes::new([3u8; 64]);
        let wrapped = wrap_seed(
            &kek(),
            &seed,
            &[1u8; 24],
            &[9u8; 16],
            Argon2Params::insecure_for_tests(),
        )
        .expect("wrap");
        let out = unwrap_seed(&kek(), &wrapped).expect("unwrap");
        assert_eq!(out.expose(), seed.expose());
    }

    #[test]
    fn the_wrong_passphrase_fails_to_unwrap() {
        let seed = SecretBytes::new([3u8; 64]);
        let wrapped = wrap_seed(
            &kek(),
            &seed,
            &[1u8; 24],
            &[9u8; 16],
            Argon2Params::insecure_for_tests(),
        )
        .expect("wrap");
        let wrong = derive_kek(
            &SecretString::new("wrong".to_owned()),
            &[9u8; 16],
            Argon2Params::insecure_for_tests(),
        )
        .expect("derive");
        assert!(matches!(
            unwrap_seed(&wrong, &wrapped),
            Err(crate::Error::BadPassphrase)
        ));
    }

    #[test]
    fn dek_is_a_pure_function_of_the_identity_key() {
        // Nothing on disk holds the DEK, so it must be reproducible from the key
        // alone, forever.
        let a = derive_dek(&[7u8; 32]);
        let b = derive_dek(&[7u8; 32]);
        let sealed = seal_row(&a, b"content", &[0u8; 24], b"memory:1").expect("seal");
        assert_eq!(
            open_row(&b, &sealed, &[0u8; 24], b"memory:1").expect("open"),
            b"content"
        );
    }

    #[test]
    fn a_different_identity_key_yields_a_different_dek() {
        let a = derive_dek(&[7u8; 32]);
        let b = derive_dek(&[8u8; 32]);
        let sealed = seal_row(&a, b"content", &[0u8; 24], b"memory:1").expect("seal");
        assert!(open_row(&b, &sealed, &[0u8; 24], b"memory:1").is_err());
    }

    /// The AAD binding is what stops a row being moved between records inside
    /// the database and silently decrypting as someone else's memory.
    #[test]
    fn a_row_moved_to_another_id_fails_to_decrypt() {
        let dek = derive_dek(&[7u8; 32]);
        let sealed = seal_row(&dek, b"saw Nan today", &[0u8; 24], b"memory:1").expect("seal");
        assert!(open_row(&dek, &sealed, &[0u8; 24], b"memory:2").is_err());
        assert!(open_row(&dek, &sealed, &[0u8; 24], b"memory:1").is_ok());
    }

    #[test]
    fn a_flipped_ciphertext_bit_is_detected() {
        let dek = derive_dek(&[7u8; 32]);
        let mut sealed = seal_row(&dek, b"content", &[0u8; 24], b"memory:1").expect("seal");
        sealed[0] ^= 1;
        assert!(matches!(
            open_row(&dek, &sealed, &[0u8; 24], b"memory:1"),
            Err(crate::Error::DecryptFailed)
        ));
    }

    /// The AAD separation, tested where it can actually be tested.
    ///
    /// Both wrappings live in one keystore file under one KEK. Length happens to
    /// distinguish them today; this is what makes the *role* distinguish them,
    /// so the property survives a future 32-byte secret being wrapped alongside.
    #[test]
    fn wrapping_roles_do_not_cross_open() {
        let kek = kek();
        let key = SecretBytes::new([0x5Au8; 32]);
        let wrapped = wrap_identity(
            &kek,
            &key,
            &[4u8; 24],
            &[9u8; 16],
            Argon2Params::insecure_for_tests(),
        )
        .expect("wrap");

        // Same bytes, same key, same nonce — only the role differs.
        let as_identity = unwrap_identity(&kek, &wrapped).expect("its own role opens it");
        assert_eq!(as_identity.expose(), key.expose());

        let cipher = XChaCha20Poly1305::new(kek.0.expose().into());
        let as_seed = cipher.decrypt(
            XNonce::from_slice(&wrapped.nonce),
            Payload {
                msg: &wrapped.ciphertext,
                aad: DEK_INFO,
            },
        );
        assert!(
            as_seed.is_err(),
            "an identity wrapping opened under the seed's AAD"
        );
    }
}
