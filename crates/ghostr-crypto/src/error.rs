//! This crate's error type.
//!
//! No variant carries key material, passphrase bytes, plaintext, or ciphertext
//! (SPEC I8). Cryptographic failures are also deliberately coarse: a decrypt
//! failure reports *that* it failed, never *why*, because a detailed oracle is
//! exactly what a padding-oracle attack needs.

/// Result alias for this crate.
pub type Result<T, E = Error> = core::result::Result<T, E>;

/// Something went wrong deriving, signing, or encrypting.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The keystore is locked and the operation needs the KEK.
    #[error("keystore is locked")]
    Locked,

    /// The supplied passphrase did not unwrap the key encryption key.
    ///
    /// Reports nothing beyond the fact of failure, and callers must rate-limit
    /// retries: Argon2id makes each attempt expensive, which only helps if an
    /// attacker cannot pipeline them.
    #[error("passphrase did not unwrap the key encryption key")]
    BadPassphrase,

    /// The mnemonic failed BIP-39 validation, checksum included.
    #[error("mnemonic is not a valid BIP-39 phrase")]
    InvalidMnemonic,

    /// A derivation path was malformed or outside the NIP-06 scheme.
    #[error("derivation path is not a valid NIP-06 path")]
    InvalidDerivationPath,

    /// A bech32 string was malformed or carried the wrong human-readable part.
    #[error("bech32 value is malformed or has the wrong prefix")]
    InvalidBech32,

    /// A public key was not a valid secp256k1 x-only point.
    #[error("public key is not a valid curve point")]
    InvalidPublicKey,

    /// A signature did not verify.
    #[error("signature verification failed")]
    BadSignature,

    /// A NIP-44 payload failed to decrypt.
    ///
    /// Covers a wrong key, a truncated payload, a bad MAC, and an unsupported
    /// version, all as one variant on purpose.
    #[error("payload failed to decrypt")]
    DecryptFailed,

    /// The NIP-44 payload declared a version this build does not implement.
    #[error("unsupported NIP-44 payload version: {version}")]
    UnsupportedVersion {
        /// The version byte found in the payload.
        version: u8,
    },

    /// The keystore backend failed.
    ///
    /// The message describes the backend operation, never its contents.
    #[error("keystore backend failed: {operation}")]
    Backend {
        /// Which operation failed, e.g. `"read wrapped seed"`.
        operation: &'static str,
    },

    /// A remote signer (NIP-46) did not answer in time or refused.
    #[error("remote signer unavailable: {reason}")]
    RemoteSigner {
        /// Why, in terms of the transport rather than the payload.
        reason: &'static str,
    },
}
