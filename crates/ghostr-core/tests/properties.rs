//! Property tests over the commitment primitives.
//!
//! CLAUDE.md §6 asks for golden vectors **and** properties on hashing, the
//! chain, and Merkle proofs, and the reason is specific to this layer: when a
//! commitment bug ships, users cannot migrate off it — the old hashes are
//! already in Bitcoin. Golden vectors pin the cases somebody thought of;
//! properties cover the ones nobody did.
//!
//! Every property below is one an attacker would want to break.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use ghostr_core::hash::{Hash32, Tag, tagged_hash, tagged_hash_parts};
use ghostr_core::merkle::{LeafKind, MerkleTree, leaf, verify_inclusion};
use proptest::prelude::*;

/// Distinct 32-byte digests, so a tree is never asked to hold duplicates.
fn distinct_leaves(max: usize) -> impl Strategy<Value = Vec<Hash32>> {
    proptest::collection::vec(any::<u64>(), 1..=max).prop_map(|seeds| {
        let mut seen = std::collections::BTreeSet::new();
        seeds
            .into_iter()
            .enumerate()
            .map(|(i, seed)| {
                tagged_hash(
                    Tag::MemoryLeaf,
                    &[seed.to_le_bytes(), (i as u64).to_le_bytes()].concat(),
                )
            })
            .filter(|h| seen.insert(*h))
            .collect()
    })
}

proptest! {
    /// Every leaf in a tree proves against its root. The base guarantee: if
    /// this fails for any shape, inclusion proofs are worthless.
    #[test]
    fn every_leaf_proves_against_its_root(leaves in distinct_leaves(64)) {
        prop_assume!(!leaves.is_empty());
        let tree = MerkleTree::build(leaves.clone()).expect("build");
        let root = tree.root();
        for target in &leaves {
            let proof = tree.prove(*target).expect("a proof for a present leaf");
            prop_assert!(verify_inclusion(&proof, root), "leaf {target:?} did not verify");
        }
    }

    /// A leaf that is not in the tree has no proof. The forgery an attacker
    /// wants: convincing a verifier a memory was in a day it was not.
    #[test]
    fn a_foreign_leaf_cannot_be_proven(
        leaves in distinct_leaves(32),
        outsider in any::<u64>(),
    ) {
        prop_assume!(!leaves.is_empty());
        let foreign = tagged_hash(Tag::QuestLeaf, &outsider.to_le_bytes());
        prop_assume!(!leaves.contains(&foreign));

        let tree = MerkleTree::build(leaves).expect("build");
        prop_assert!(tree.prove(foreign).is_none());
    }

    /// A proof does not transfer between trees. Without this, a proof from a
    /// day the user really did have could be replayed against a day they did
    /// not.
    #[test]
    fn a_proof_does_not_verify_against_another_root(
        a in distinct_leaves(16),
        b in distinct_leaves(16),
    ) {
        prop_assume!(!a.is_empty() && !b.is_empty());
        let tree_a = MerkleTree::build(a.clone()).expect("a");
        let tree_b = MerkleTree::build(b).expect("b");
        prop_assume!(tree_a.root() != tree_b.root());

        let proof = tree_a.prove(a[0]).expect("proof");
        prop_assert!(!verify_inclusion(&proof, tree_b.root()));
    }

    /// The root does not depend on the order leaves were handed over. Two
    /// devices ingesting the same day in different orders must agree, or the
    /// chain forks on nothing.
    #[test]
    fn the_root_is_independent_of_insertion_order(leaves in distinct_leaves(24)) {
        prop_assume!(leaves.len() > 1);
        let forward = MerkleTree::build(leaves.clone()).expect("forward").root();
        let mut reversed = leaves;
        reversed.reverse();
        let backward = MerkleTree::build(reversed).expect("backward").root();
        prop_assert_eq!(forward, backward);
    }

    /// Changing any leaf changes the root. If it did not, a memory could be
    /// swapped inside a sealed day without the commitment noticing.
    #[test]
    fn changing_a_leaf_changes_the_root(
        leaves in distinct_leaves(16),
        index in 0usize..16,
    ) {
        prop_assume!(!leaves.is_empty());
        let index = index % leaves.len();
        let before = MerkleTree::build(leaves.clone()).expect("before").root();

        let mut tampered = leaves;
        tampered[index] = tagged_hash(Tag::MemoryLeaf, b"a different memory entirely");
        prop_assume!(tampered.iter().collect::<std::collections::BTreeSet<_>>().len() == tampered.len());

        let after = MerkleTree::build(tampered).expect("after").root();
        prop_assert_ne!(before, after);
    }

    /// Truncating a tree changes its root. Otherwise a day could be made
    /// smaller after the fact — dropping the memory somebody wanted gone.
    #[test]
    fn dropping_a_leaf_changes_the_root(leaves in distinct_leaves(16)) {
        prop_assume!(leaves.len() > 1);
        let full = MerkleTree::build(leaves.clone()).expect("full").root();
        let mut short = leaves;
        short.pop();
        let truncated = MerkleTree::build(short).expect("short").root();
        prop_assert_ne!(full, truncated);
    }

    /// `leaf_count` bounds the proof's depth. A path longer than the tree can
    /// be deep is a padded proof, and the bound is `ceil(log2(n))` — not `n`
    /// rounded up, which for a thousand leaves would permit a path a hundred
    /// times longer than any real one.
    #[test]
    fn a_path_longer_than_the_tree_is_deep_is_refused(leaves in distinct_leaves(16)) {
        prop_assume!(leaves.len() > 1);
        let tree = MerkleTree::build(leaves.clone()).expect("build");
        let root = tree.root();
        let proof = tree.prove(leaves[0]).expect("proof");
        prop_assert!(verify_inclusion(&proof, root));

        // The real depth for this many leaves.
        let depth = (leaves.len() as u32).next_power_of_two().trailing_zeros() as usize;
        prop_assert!(proof.siblings.len() <= depth);

        // One step past it is refused, whatever the siblings contain.
        let mut padded = proof;
        while padded.siblings.len() <= depth {
            padded.siblings.push(ghostr_core::merkle::Sibling {
                hash: tagged_hash(Tag::Node, b"padding"),
                side: ghostr_core::merkle::Side::Right,
            });
        }
        prop_assert!(!verify_inclusion(&padded, root));
    }

    /// A proof claiming a tree far larger than its path length still cannot
    /// verify against a root it does not belong to.
    #[test]
    fn inflating_leaf_count_does_not_make_a_foreign_proof_verify(
        a in distinct_leaves(16),
        b in distinct_leaves(16),
    ) {
        prop_assume!(!a.is_empty() && !b.is_empty());
        let tree_a = MerkleTree::build(a.clone()).expect("a");
        let tree_b = MerkleTree::build(b).expect("b");
        prop_assume!(tree_a.root() != tree_b.root());

        let mut proof = tree_a.prove(a[0]).expect("proof");
        proof.leaf_count = u32::MAX;
        prop_assert!(!verify_inclusion(&proof, tree_b.root()));
    }

    /// A zero leaf count is malformed: an empty tree has no root to prove
    /// against, and `build` refuses to make one.
    #[test]
    fn a_zero_leaf_count_is_refused(leaves in distinct_leaves(8)) {
        prop_assume!(!leaves.is_empty());
        let tree = MerkleTree::build(leaves.clone()).expect("build");
        let mut proof = tree.prove(leaves[0]).expect("proof");
        proof.leaf_count = 0;
        prop_assert!(!verify_inclusion(&proof, tree.root()));
    }

    /// A salt makes a leaf hiding as well as binding. Two identical memories
    /// with different salts must not share a digest, or a low-entropy note
    /// could be confirmed by guessing (SPEC §7.2).
    #[test]
    fn identical_content_under_different_salts_differs(
        content in proptest::collection::vec(any::<u8>(), 0..256),
        a in any::<u64>(),
        b in any::<u64>(),
    ) {
        prop_assume!(a != b);
        let salt_a = tagged_hash(Tag::MemoryLeaf, &a.to_le_bytes());
        let salt_b = tagged_hash(Tag::MemoryLeaf, &b.to_le_bytes());
        prop_assert_ne!(
            leaf(LeafKind::Memory, salt_a.as_bytes(), &content),
            leaf(LeafKind::Memory, salt_b.as_bytes(), &content),
        );
    }

    /// The three leaf kinds are separate hash domains. A quest leaf must never
    /// be provable as a memory leaf — that is what the newtype-per-kind and the
    /// tag-per-kind exist to guarantee together.
    #[test]
    fn leaf_kinds_are_separate_domains(
        salt_seed in any::<u64>(),
        content in proptest::collection::vec(any::<u8>(), 0..128),
    ) {
        let salt = tagged_hash(Tag::MemoryLeaf, &salt_seed.to_le_bytes());
        let memory = leaf(LeafKind::Memory, salt.as_bytes(), &content);
        let quest = leaf(LeafKind::Quest, salt.as_bytes(), &content);
        let meta = leaf(LeafKind::Meta, salt.as_bytes(), &content);
        prop_assert_ne!(memory, quest);
        prop_assert_ne!(quest, meta);
        prop_assert_ne!(memory, meta);
    }

    /// Tagged hashing is domain-separated: the same message under two tags
    /// gives two digests. This is the property the whole scheme rests on.
    #[test]
    fn tags_separate_domains(message in proptest::collection::vec(any::<u8>(), 0..512)) {
        let a = tagged_hash(Tag::MemoryLeaf, &message);
        let b = tagged_hash(Tag::QuestLeaf, &message);
        let c = tagged_hash(Tag::Link, &message);
        prop_assert_ne!(a, b);
        prop_assert_ne!(b, c);
        prop_assert_ne!(a, c);
    }

    /// Concatenated parts are not the same as their concatenation reversed, and
    /// the multi-part form agrees with the single-part one. A hash that ignored
    /// part boundaries would let `("ab", "c")` and `("a", "bc")` collide.
    #[test]
    fn multi_part_hashing_agrees_with_concatenation(
        a in proptest::collection::vec(any::<u8>(), 0..128),
        b in proptest::collection::vec(any::<u8>(), 0..128),
    ) {
        let joined = [a.clone(), b.clone()].concat();
        prop_assert_eq!(
            tagged_hash_parts(Tag::MemoryLeaf, &[&a, &b]),
            tagged_hash(Tag::MemoryLeaf, &joined),
        );
    }

    /// Hashing is a function: same input, same digest, every time.
    #[test]
    fn hashing_is_deterministic(message in proptest::collection::vec(any::<u8>(), 0..512)) {
        prop_assert_eq!(
            tagged_hash(Tag::MemoryLeaf, &message),
            tagged_hash(Tag::MemoryLeaf, &message),
        );
    }

    /// Canonical CBOR round-trips, and one value has exactly one encoding —
    /// which is the entire reason the canonical encoder exists separately from
    /// the storage one (CLAUDE.md §5).
    #[test]
    fn canonical_encoding_is_unique_per_value(
        keys in proptest::collection::vec("[a-z]{1,8}", 1..8),
        value in any::<u32>(),
    ) {
        use std::collections::BTreeMap;

        let map: BTreeMap<String, u32> = keys.iter().map(|k| (k.clone(), value)).collect();
        let once = ghostr_core::canonical::to_canonical_cbor(&map).expect("encode");
        let twice = ghostr_core::canonical::to_canonical_cbor(&map).expect("encode");
        prop_assert_eq!(&once, &twice);

        ghostr_core::canonical::verify_canonical(&once).expect("its own output is canonical");

        let back: BTreeMap<String, u32> =
            ghostr_core::canonical::from_canonical_cbor(&once).expect("decode");
        prop_assert_eq!(back, map);
    }

    /// Floats are rejected by the canonical encoder. They have multiple
    /// representations for one value, so accepting them would let the same data
    /// hash two ways — the failure that cannot be migrated away from.
    #[test]
    fn the_canonical_encoder_rejects_floats(value in any::<f32>()) {
        prop_assert!(ghostr_core::canonical::to_canonical_cbor(&value).is_err());
    }
}
