//! Passphrase stretching and the at-rest key hierarchy (SPEC §10.1).
//!
//! ```text
//! passphrase --Argon2id--> KEK --wraps--> DEK --encrypts--> database + blobs
//!  (m=256MiB, t=3, p=4)          (XChaCha20-Poly1305)
//! ```
//!
//! Two decisions worth stating plainly:
//!
//! - **The DEK is wrapped, not derived.** So changing a passphrase rewraps one
//!   32-byte key instead of re-encrypting the entire corpus.
//! - **Argon2id at 256 MiB.** Memory-hardness is what turns a stolen database
//!   from a GPU-farm problem into a per-device one. It also means unlocking
//!   costs a real fraction of a second and allocates a quarter gigabyte, which
//!   is a deliberate trade, not an oversight (THREAT_MODEL §T1).

use crate::secret::{SecretBytes, SecretString};

/// Argon2id parameters. Stored alongside the wrapped key so that raising the
/// cost later does not strand existing vaults.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
}

/// The key encryption key, derived from the passphrase.
#[derive(Debug)]
pub struct Kek(SecretBytes<32>);

/// The data encryption key, which actually encrypts the corpus.
#[derive(Debug)]
pub struct Dek(SecretBytes<32>);

/// A DEK encrypted under a KEK, as persisted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WrappedDek {
    /// The wrapped key bytes.
    pub ciphertext: Vec<u8>,
    /// The AEAD nonce.
    pub nonce: [u8; 24],
    /// The salt the KEK was derived with.
    pub salt: [u8; 16],
    /// The parameters in force when this was wrapped.
    pub params: Argon2Params,
}

/// Derives a KEK from a passphrase.
///
/// # Errors
///
/// Returns an error if the Argon2id parameters are invalid or memory cannot be
/// allocated — on a memory-constrained device that is a real, reportable
/// condition rather than a reason to silently weaken the parameters.
pub fn derive_kek(
    passphrase: &SecretString,
    salt: &[u8; 16],
    params: Argon2Params,
) -> crate::Result<Kek> {
    todo!("Argon2id with the supplied parameters")
}

/// Wraps a DEK under a KEK.
///
/// # Errors
///
/// Returns an error if encryption fails.
pub fn wrap_dek(
    kek: &Kek,
    dek: &Dek,
    nonce: &[u8; 24],
    salt: &[u8; 16],
) -> crate::Result<WrappedDek> {
    todo!("XChaCha20-Poly1305 encrypt the DEK under the KEK")
}

/// Unwraps a DEK.
///
/// # Errors
///
/// Returns [`Error::BadPassphrase`](crate::Error::BadPassphrase) if the KEK does
/// not authenticate the wrapped key. The AEAD tag failing *is* the wrong-password
/// signal — there is no separate verifier to check first, and no way to
/// distinguish a wrong passphrase from a corrupted file.
pub fn unwrap_dek(kek: &Kek, wrapped: &WrappedDek) -> crate::Result<Dek> {
    todo!("XChaCha20-Poly1305 decrypt, mapping tag failure to BadPassphrase")
}

/// Encrypts a row payload under the DEK.
///
/// `aad` binds the ciphertext to its row (`row_type || row_id`), so a row
/// swapped inside the database fails to decrypt rather than silently returning
/// another record's content (SPEC §10.2).
///
/// # Errors
///
/// Returns an error if encryption fails.
pub fn seal_row(
    dek: &Dek,
    plaintext: &[u8],
    nonce: &[u8; 24],
    aad: &[u8],
) -> crate::Result<Vec<u8>> {
    todo!("XChaCha20-Poly1305 encrypt with the row AAD")
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
    todo!("XChaCha20-Poly1305 decrypt with the row AAD")
}
