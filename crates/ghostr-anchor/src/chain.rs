//! The pure commitment chain (SPEC §7.3).
//!
//! No I/O, no async, no clock, no entropy. Every function is a total function of
//! its arguments, which is what makes this testable with fixed vectors and
//! property tests rather than with a mock.
//!
//! # The scheme
//!
//! ```text
//! leaf      = H_tag(<kind>, salt || canonical_cbor(value))
//! root_n    = merkle_root(sorted([meta_leaf, memory_leaf*, quest_leaf*]))
//! link_0    = H_tag(Genesis, identity_pubkey || genesis_timestamp || chain_id)
//! link_n    = H_tag(Link, link_{n-1} || root_n || u64_be(seq) || date || tz)
//! ```
//!
//! # Why this shape
//!
//! - **Append-only.** Changing anything in day 40 changes `root_40`, therefore
//!   `link_40`, therefore every link after it. Anchoring the tip freezes
//!   everything behind it.
//! - **Gapless.** `seq` is in the preimage, so a day cannot be silently dropped.
//! - **Selectively revealable.** One memory can be proven without disclosing
//!   anything else from its day.
//! - **Crypto-shreddable.** Salted leaves mean content and salt can be destroyed
//!   while the chain still verifies (SPEC Q6).

use chrono::NaiveDate;
use chrono_tz::Tz;
use ghostr_core::hash::Hash32;
use ghostr_core::identity::PublicKey;
use ghostr_core::ids::ChainId;
use ghostr_core::merkle::{LeafKind, MerkleProof};
use ghostr_core::time::Timestamp;

/// Builds and verifies chain commitments.
///
/// A trait rather than free functions so a future scheme version can coexist
/// with v1 during a migration. There will only ever be one implementation at a
/// time in production, and old chains must stay verifiable forever.
pub trait CommitmentChain: Send + Sync {
    /// The scheme version this implements.
    ///
    /// Recorded in the ghost manifest so a verifier knows which rules to apply
    /// without guessing from the data.
    fn version(&self) -> u16;

    /// The genesis link, which anchors the chain to an identity.
    ///
    /// `chain_id` is in the preimage so two chains for the same identity cannot
    /// produce colliding links.
    fn genesis(&self, identity: &PublicKey, chain_id: ChainId, at: Timestamp) -> Hash32;

    /// A salted leaf.
    ///
    /// The salt is what makes the leaf *hiding* as well as binding. A memory is
    /// often low-entropy — "saw Nan today" is perhaps 30 guessable bits — and an
    /// unsalted commitment to it is one anyone can confirm by guessing
    /// (SPEC §7.2).
    fn leaf(&self, kind: LeafKind, salt: &[u8; 32], canonical_bytes: &[u8]) -> Hash32;

    /// The Merkle root over one window's leaves.
    ///
    /// Sorts by digest first, so the root is a function of the *set* of leaves
    /// rather than of collection order — two devices compiling the same day
    /// cannot disagree because they walked the store differently.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Core`](crate::Error::Core) if the leaf set is empty or
    /// contains duplicates.
    fn root(&self, leaves: &[Hash32]) -> crate::Result<Hash32>;

    /// One chain link.
    ///
    /// `tz` is in the preimage as its IANA name, so a day sealed in Bangkok and
    /// a day sealed in Berlin are distinguishable even at the same instant.
    fn link(&self, prev: Hash32, root: Hash32, seq: u64, date: NaiveDate, tz: &Tz) -> Hash32;

    /// An inclusion proof for one leaf.
    fn inclusion_proof(&self, leaves: &[Hash32], target: Hash32) -> Option<MerkleProof>;

    /// Verifies an inclusion proof against a root.
    ///
    /// Total: returns `false` rather than erroring, so a verifier can process a
    /// batch without unwinding.
    fn verify_inclusion(&self, proof: &MerkleProof, root: Hash32) -> bool;

    /// Recomputes every link over a run of records.
    ///
    /// The core of `gst verify`. Reports the *first* bad sequence, because every
    /// link after a break also fails and listing them buries the one that
    /// matters.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ChainBroken`](crate::Error::ChainBroken) or
    /// [`Error::ChainGap`](crate::Error::ChainGap).
    fn verify_run(&self, records: &[ChainRecord]) -> crate::Result<()>;
}

/// The minimum needed to verify one link, without the footage content.
///
/// A third party can be handed a run of these and check chain integrity while
/// learning nothing beyond how many days there were and when.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChainRecord {
    /// Sequence number.
    pub seq: u64,
    /// Local calendar date of the cutoff.
    pub date: NaiveDate,
    /// Zone in effect.
    pub tz: Tz,
    /// Merkle root over the day's leaves.
    pub root: Hash32,
    /// Previous link.
    pub prev_link: Hash32,
    /// This link.
    pub link: Hash32,
}

/// Everything needed to prove one memory existed on one day, and nothing more.
///
/// The selective-disclosure unit. Hands over a memory, its salt, its path to a
/// root, and the links from that day forward to an anchored tip — disclosing
/// nothing else from the day, and nothing at all from any other day.
#[derive(Debug, Clone, PartialEq)]
pub struct DisclosureBundle {
    /// The revealed memory, canonically encoded.
    pub canonical_memory: Vec<u8>,
    /// Its blinding salt, without which the leaf cannot be recomputed.
    pub salt: [u8; 32],
    /// Path from the leaf to the day's root.
    pub inclusion: MerkleProof,
    /// Links from the revealing day up to an anchored tip.
    pub links: Vec<ChainRecord>,
    /// The anchored tip's proof.
    pub anchor: crate::ots::Proof,
}
