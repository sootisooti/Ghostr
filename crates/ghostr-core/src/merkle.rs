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

use crate::hash::{Hash32, Tag, tagged_hash_parts};

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
    /// A verdict, in the day it was given rather than the day its quest was
    /// issued.
    ///
    /// Those are often different days — a quest stays answerable for 48 hours —
    /// and a sealed footage is immutable (I2), so a verdict cannot be added to
    /// the tree of the day that asked. It is committed where it happened.
    Verdict,
    /// The footage metadata: sequence, dates, window, counts.
    Meta,
}

impl LeafKind {
    /// The hash tag for this leaf kind.
    #[must_use]
    pub const fn tag(self) -> Tag {
        match self {
            Self::Memory => Tag::MemoryLeaf,
            Self::Quest => Tag::QuestLeaf,
            Self::Verdict => Tag::VerdictLeaf,
            Self::Meta => Tag::MetaLeaf,
        }
    }
}

/// Computes a salted leaf digest.
///
/// The salt is what makes the leaf *hiding* as well as binding. A memory is
/// often low-entropy — "saw Nan today" is perhaps 30 guessable bits — and an
/// unsalted commitment to it is one anyone can confirm by guessing. Deleting
/// the salt along with the content is also what makes crypto-shredding work
/// (SPEC §7.2, Q6).
#[must_use]
pub fn leaf(kind: LeafKind, salt: &[u8; 32], canonical_bytes: &[u8]) -> Hash32 {
    tagged_hash_parts(kind.tag(), &[salt, canonical_bytes])
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
    pub fn build(mut leaves: Vec<Hash32>) -> crate::Result<Self> {
        if leaves.is_empty() {
            return Err(crate::Error::Canonical {
                reason: "merkle tree needs at least the metadata leaf",
            });
        }
        leaves.sort_unstable();
        if leaves.windows(2).any(|w| w[0] == w[1]) {
            return Err(crate::Error::Canonical {
                reason: "duplicate merkle leaf",
            });
        }
        Ok(Self { leaves })
    }

    /// The tree's root.
    #[must_use]
    pub fn root(&self) -> Hash32 {
        let mut level = self.leaves.clone();
        while level.len() > 1 {
            level = level
                .chunks(2)
                .map(|pair| match pair {
                    [a, b] => tagged_hash_parts(Tag::Node, &[a.as_bytes(), b.as_bytes()]),
                    // An odd node is promoted unchanged rather than paired with
                    // itself. Duplicating it is the CVE-2012-2459 shape, where
                    // two different leaf sets produce the same root.
                    [a] => *a,
                    _ => unreachable!("chunks(2) yields one or two elements"),
                })
                .collect();
        }
        level[0]
    }

    /// The sorted leaves.
    #[must_use]
    pub fn leaves(&self) -> &[Hash32] {
        &self.leaves
    }

    /// Produces an inclusion proof for `target`, or `None` if it is not present.
    #[must_use]
    pub fn prove(&self, target: Hash32) -> Option<MerkleProof> {
        let mut index = self.leaves.binary_search(&target).ok()?;
        let mut level = self.leaves.clone();
        let mut siblings = Vec::new();

        while level.len() > 1 {
            let is_right = index % 2 == 1;
            let sibling_index = if is_right { index - 1 } else { index + 1 };
            if let Some(hash) = level.get(sibling_index) {
                siblings.push(Sibling {
                    hash: *hash,
                    side: if is_right { Side::Left } else { Side::Right },
                });
            }
            // A promoted odd node has no sibling at this level, so nothing is
            // pushed and the path simply skips a step.
            level = level
                .chunks(2)
                .map(|pair| match pair {
                    [a, b] => tagged_hash_parts(Tag::Node, &[a.as_bytes(), b.as_bytes()]),
                    [a] => *a,
                    _ => unreachable!("chunks(2) yields one or two elements"),
                })
                .collect();
            index /= 2;
        }

        Some(MerkleProof {
            leaf: target,
            siblings,
            leaf_count: u32::try_from(self.leaves.len()).unwrap_or(u32::MAX),
        })
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
    // A path longer than the tree can be deep is a padded proof from a smaller
    // tree, replayed against a larger root.
    //
    // The bound is the tree's *depth*, `ceil(log2(n))`, not `n` rounded up to a
    // power of two — those differ by orders of magnitude (for 1000 leaves: 10
    // against 1024), and the looser one is barely a bound at all.
    //
    // It is an upper bound rather than an equality because a promoted odd node
    // skips a level, so two leaves in the same tree can have paths of different
    // lengths. `leaf_count` is therefore a sanity check here, not a binding
    // one: what actually binds a proof to a day is the caller comparing it
    // against the `leaf_count` recorded in that day's sealed commitment.
    let leaf_count = usize::try_from(proof.leaf_count).unwrap_or(usize::MAX);
    if leaf_count == 0 {
        return false;
    }
    let max_depth = if leaf_count == 1 {
        0
    } else {
        leaf_count.next_power_of_two().trailing_zeros() as usize
    };
    if proof.siblings.len() > max_depth {
        return false;
    }
    let mut current = proof.leaf;
    for sibling in &proof.siblings {
        current = match sibling.side {
            Side::Left => {
                tagged_hash_parts(Tag::Node, &[sibling.hash.as_bytes(), current.as_bytes()])
            }
            Side::Right => {
                tagged_hash_parts(Tag::Node, &[current.as_bytes(), sibling.hash.as_bytes()])
            }
        };
    }
    current == root
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaves(n: u8) -> Vec<Hash32> {
        (0..n)
            .map(|i| crate::hash::tagged_hash(Tag::MemoryLeaf, &[i]))
            .collect()
    }

    #[test]
    fn root_is_independent_of_insertion_order() {
        let mut a = leaves(7);
        let mut b = a.clone();
        b.reverse();
        a.swap(0, 3);
        assert_eq!(
            MerkleTree::build(a).expect("build").root(),
            MerkleTree::build(b).expect("build").root(),
        );
    }

    #[test]
    fn every_leaf_proves_against_the_root() {
        for n in 1..=17u8 {
            let tree = MerkleTree::build(leaves(n)).expect("build");
            let root = tree.root();
            for leaf in tree.leaves() {
                let proof = tree.prove(*leaf).expect("leaf is present");
                assert!(verify_inclusion(&proof, root), "n={n} leaf={leaf:?}");
            }
        }
    }

    #[test]
    fn a_foreign_leaf_does_not_verify() {
        let tree = MerkleTree::build(leaves(8)).expect("build");
        let root = tree.root();
        let outsider = crate::hash::tagged_hash(Tag::MemoryLeaf, b"not in the tree");
        assert!(tree.prove(outsider).is_none());

        // Substituting the leaf in an otherwise valid proof must fail.
        let mut proof = tree.prove(tree.leaves()[0]).expect("present");
        proof.leaf = outsider;
        assert!(!verify_inclusion(&proof, root));
    }

    #[test]
    fn empty_and_duplicate_leaf_sets_are_rejected() {
        assert!(MerkleTree::build(Vec::new()).is_err());
        let dup = crate::hash::tagged_hash(Tag::MemoryLeaf, b"x");
        assert!(MerkleTree::build(vec![dup, dup]).is_err());
    }

    #[test]
    fn a_padded_proof_from_a_smaller_tree_is_rejected() {
        let tree = MerkleTree::build(leaves(4)).expect("build");
        let mut proof = tree.prove(tree.leaves()[0]).expect("present");
        proof.leaf_count = 1;
        assert!(!verify_inclusion(&proof, tree.root()));
    }

    #[test]
    fn salted_leaves_differ_for_identical_content() {
        // The blinding property: the same content under two salts must not
        // produce the same leaf, or a low-entropy memory could be confirmed by
        // guessing (SPEC §7.2).
        let a = leaf(LeafKind::Memory, &[1u8; 32], b"saw Nan today");
        let b = leaf(LeafKind::Memory, &[2u8; 32], b"saw Nan today");
        assert_ne!(a, b);
    }

    #[test]
    fn leaf_kinds_are_separate_domains() {
        let salt = [7u8; 32];
        let m = leaf(LeafKind::Memory, &salt, b"x");
        let q = leaf(LeafKind::Quest, &salt, b"x");
        let t = leaf(LeafKind::Meta, &salt, b"x");
        assert_ne!(m, q);
        assert_ne!(q, t);
        assert_ne!(m, t);
    }
}
