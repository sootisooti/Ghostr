//! [`Identity`] — the user, the ghost, and the binding between them.
//!
//! Public key material only. Secrets live behind a
//! [`KeyRef`] in `ghostr-crypto`'s keystore and never appear in a domain type
//! (SPEC I8, ARCHITECTURE §3 rule 4).
//!
//! The user and the ghost hold **separate keypairs** derived from one seed
//! (SPEC §8.1), which buys three things: the ghost can post without the identity
//! key entering a hot process, a compromised ghost key is revocable without
//! burning the social graph, and anything signed by the ghost key is
//! self-evidently ghost-authored (SPEC I10).

use serde::{Deserialize, Serialize};

use crate::ids::ChainId;
use crate::time::Timestamp;

/// A secp256k1 x-only public key, as used by nostr (BIP-340).
///
/// Public data, so a hex `Debug` rendering is safe.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PublicKey([u8; 32]);

impl PublicKey {
    /// Wraps 32 raw bytes.
    ///
    /// Does not validate that the bytes are a curve point; that check belongs to
    /// `ghostr-crypto`, which owns the curve. This type is a carrier.
    #[must_use]
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// The raw bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Lowercase hex, the form nostr events use.
    #[must_use]
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// The first eight hex digits, for display in lists.
    #[must_use]
    pub fn short(&self) -> String {
        self.to_hex()[..8].to_owned()
    }

    /// Parses a 64-digit lowercase hex key.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Canonical`](crate::Error::Canonical) if the input is not
    /// 64 hex digits. Curve validity is checked by `ghostr-crypto`, which owns
    /// the curve; this type is a carrier.
    pub fn from_hex(s: &str) -> crate::Result<Self> {
        let mut out = [0u8; 32];
        hex::decode_to_slice(s, &mut out).map_err(|_| crate::Error::Canonical {
            reason: "not a 32-byte hex public key",
        })?;
        Ok(Self(out))
    }
}

impl core::fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl core::fmt::Display for PublicKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.to_hex())
    }
}

/// A NIP-19 `npub`-encoded public key.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Npub(String);

impl Npub {
    /// Wraps an already-validated `npub` string.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Canonical`](crate::Error::Canonical) if the string is not
    /// a well-formed `npub1...` bech32 encoding.
    pub fn parse(s: String) -> crate::Result<Self> {
        if !s.starts_with("npub1") || s.len() < 60 {
            return Err(crate::Error::Canonical {
                reason: "not an npub1 bech32 string",
            });
        }
        Ok(Self(s))
    }

    /// Wraps a string produced by this crate's own encoder.
    ///
    /// Skips the shape check because `ghostr-crypto` has already done bech32
    /// validation, which is stricter than anything this crate can do without
    /// depending on a bech32 implementation.
    #[must_use]
    pub fn from_encoded(s: String) -> Self {
        Self(s)
    }

    /// The encoded string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// An opaque handle to a key held by the keystore.
///
/// The whole point of this type is what it does *not* contain. Code that needs a
/// signature holds a `KeyRef` and calls `Signer`; only `ghostr-crypto` can turn
/// one into key material. That is what lets a NIP-46 remote signer or a hardware
/// device drop in without touching a single call site.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct KeyRef {
    /// Which NIP-06 account this refers to.
    pub account: Account,
}

/// The four NIP-06 accounts Ghostr derives (SPEC §8.1).
///
/// Separation is what makes selective disclosure possible: anchor receipts can
/// be published from [`Account::Anchor`] proving a chain is live without
/// revealing whose chain it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Account {
    /// `m/44'/1237'/0'/0/0` — the user's nostr identity. Signs manifests and
    /// revocations. Never signs ghost-generated content.
    Identity,
    /// `m/44'/1237'/1'/0/0` — the ghost. Rotatable.
    Ghost,
    /// `m/44'/1237'/2'/0/0` — publishes anchor receipts. Unlinkable from
    /// [`Account::Identity`] unless deliberately linked.
    Anchor,
    /// `m/44'/1237'/3'/0/0` — encrypts app data published to relays.
    Data,
}

impl Account {
    /// The BIP-32 account index.
    #[must_use]
    pub fn index(self) -> u32 {
        match self {
            Self::Identity => 0,
            Self::Ghost => 1,
            Self::Anchor => 2,
            Self::Data => 3,
        }
    }

    /// The full NIP-06 derivation path.
    #[must_use]
    pub fn derivation_path(self) -> String {
        format!("m/44'/1237'/{}'/0/0", self.index())
    }
}

/// A user identity.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Identity {
    /// The identity public key. Also the nostr identity.
    pub pubkey: PublicKey,
    /// NIP-19 encoding of [`Identity::pubkey`].
    pub npub: Npub,
    /// How the key was derived.
    pub derivation: DerivationInfo,
    /// Handle into the keystore. Never the key itself (SPEC I8).
    pub signing_key: KeyRef,
    /// The ghost, once one has been created.
    pub ghost: Option<GhostBinding>,
    /// Which chain belongs to this identity.
    pub chain_id: ChainId,
    /// Relay preferences.
    pub relays: Vec<RelayPolicy>,
    /// When this identity was created.
    pub created_at: Timestamp,
}

/// How a key was derived.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DerivationInfo {
    /// The NIP-06 path.
    pub path: String,
    /// Which account.
    pub account: Account,
    /// Whether the seed was generated by Ghostr or imported.
    pub imported: bool,
}

/// The user's attestation of their ghost.
///
/// This is what makes "provably his ghost" a checkable statement rather than a
/// claim: a third party fetches the manifest, verifies the identity key's
/// signature, and knows which pubkey the user vouches for. Revocation is a
/// status change, not a key burn (SPEC §8.2).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GhostBinding {
    /// The ghost's public key.
    pub pubkey: PublicKey,
    /// When the ghost was created.
    pub created_at: Timestamp,
    /// Where the signed manifest lives (kind 31780).
    pub manifest_ref: EventCoordinate,
    /// Whether the ghost is live, paused, or revoked.
    pub status: GhostStatus,
    /// When it was revoked, if it was.
    pub revoked_at: Option<Timestamp>,
}

/// Whether a ghost is live.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum GhostStatus {
    /// Operating.
    Active,
    /// Temporarily paused by the user.
    Suspended,
    /// Permanently revoked.
    Revoked,
}

/// A NIP-01 addressable event coordinate: `kind:pubkey:d-tag`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EventCoordinate {
    /// The event kind.
    pub kind: u16,
    /// The author.
    pub pubkey: PublicKey,
    /// The `d` tag identifying the addressable event.
    pub d_tag: String,
}

/// What a relay is used for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayPolicy {
    /// The relay URL.
    pub url: String,
    /// Whether to read from it.
    pub read: bool,
    /// Whether to write to it.
    pub write: bool,
    /// Whether events sent here are wrapped in NIP-59 gift wrap.
    ///
    /// Hides kind and author from the relay at the cost of discoverability
    /// (SPEC §10.3).
    pub gift_wrap: bool,
}
