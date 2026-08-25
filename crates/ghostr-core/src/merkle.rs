//! The Merkle tree over one day's leaves, and inclusion proofs against it.
//!
//! Structure follows RFC 6962: leaves and internal nodes are hashed under
//! different tags, so an attacker cannot present an internal node as a leaf.
//! Leaves are sorted by digest before the tree is built, which makes the root a
//! function of the *set* of leaves rather than of the order they were collected
//! in — two devices compiling the same day cannot disagree about the root
//! because they walked the store differently.
//!
//! This is what makes selective disclosure work: to prove one memory existed on
//! day 40, reveal that memory, its salt, and its path to `root_40`. Nothing else
//! from that day is disclosed (SPEC §7.3).

use serde::{Deserialize, Serialize};

use crate::hash::Hash32;

/// Which kind of leaf a digest commits to.
///
/// Selects the tag, and therefore keeps the three leaf kinds in separate hash
/// domains within one tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum LeafKind {
    /// A memory, salted with its own 32 random bytes.
    Memory,
    /// A quest and its answer commitment, blinded with the quest nonce.
    Quest,
    /// The footage metadata: sequence, dates, window, counts.
    Meta,
}

/// A Merkle tree over one sealing window's leaves.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MerkleTree {
    /// Leaf digests, sorted ascending.
    leaves: Vec<Hash32>,
}

impl MerkleTree {
    /// Builds a tree, sorting the leaves by digest.
    ///
    /// Duplicate digests are an error rather than a silently deduplicated set:
    /// two identical leaves mean either a bug or a salt reuse, and both are
    /// worth failing loudly for.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Canonical`](crate::Error::Canonical) if `leaves` is
    /// empty or contains duplicates. An empty day still has a [`LeafKind::Meta`]
    /// leaf, so an empty tree indicates a caller bug (SPEC §3.4).
    pub fn build(leaves: Vec<Hash32>) -> crate::Result<Self> {
        todo!("sort, reject empty and duplicate leaf sets")
    }

    /// The tree's root.
    #[must_use]
    pub fn root(&self) -> Hash32 {
        todo!("fold pairs under Tag::Node, duplicating the last node on odd levels")
    }

    /// The sorted leaves.
    #[must_use]
    pub fn leaves(&self) -> &[Hash32] {
        &self.leaves
    }

    /// Produces an inclusion proof for `target`, or `None` if it is not present.
    #[must_use]
    pub fn prove(&self, target: Hash32) -> Option<MerkleProof> {
        todo!("collect the sibling path from `target` up to the root")
    }
}

/// A path from a leaf to a root.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MerkleProof {
    /// The leaf being proven.
    pub leaf: Hash32,
    /// Sibling digests, ordered leaf-to-root.
    pub siblings: Vec<Sibling>,
    /// Number of leaves in the tree, which pins the shape of the path.
    ///
    /// Without it, a proof from a small tree could be replayed against a larger
    /// one by padding the sibling list.
    pub leaf_count: u32,
}

/// One step of a [`MerkleProof`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sibling {
    /// The sibling digest.
    pub hash: Hash32,
    /// Which side the sibling sits on.
    pub side: Side,
}

/// Which side of a pair a sibling occupies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Side {
    /// Sibling is the left child; the path node is the right.
    Left,
    /// Sibling is the right child; the path node is the left.
    Right,
}

/// Verifies an inclusion proof against a root.
///
/// Pure and total: never panics, returns `false` for a malformed proof rather
/// than erroring, so a verifier can process a batch without unwinding.
#[must_use]
pub fn verify_inclusion(proof: &MerkleProof, root: Hash32) -> bool {
    todo!("fold the sibling path from the leaf and compare against `root`")
}
