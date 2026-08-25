//! The pure commitment chain (SPEC §7.3).
//!
//! No I/O, no async, no clock, no entropy. Every function is a total function of
//! its arguments, which is what makes this testable with fixed vectors rather
//! than a mock.
//!
//! # The scheme
//!
//! ```text
//! leaf      = H_tag(<kind>, salt || canonical_cbor(value))
//! root_n    = merkle_root(sorted([meta_leaf, memory_leaf*]))
//! link_0    = H_tag(Genesis, identity_pubkey || genesis_millis || chain_id)
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
use ghostr_core::hash::{Hash32, Tag, tagged_hash_parts};
use ghostr_core::identity::PublicKey;
use ghostr_core::ids::ChainId;
use ghostr_core::merkle::{LeafKind, MerkleProof, MerkleTree, leaf, verify_inclusion};
use ghostr_core::time::Timestamp;
use serde::{Deserialize, Serialize};

/// The commitment scheme version this build implements.
pub const CHAIN_VERSION: u16 = 1;

/// The genesis link, which anchors a chain to an identity.
///
/// `chain_id` is in the preimage so two chains for the same identity cannot
/// produce colliding links.
#[must_use]
pub fn genesis(identity: &PublicKey, chain_id: ChainId, at: Timestamp) -> Hash32 {
    tagged_hash_parts(
        Tag::Genesis,
        &[
            identity.as_bytes(),
            &at.utc_millis().to_be_bytes(),
            chain_id.as_uuid().as_bytes(),
        ],
    )
}

/// A salted leaf for one memory.
///
/// The salt is what makes the leaf hiding as well as binding: "saw Nan today" is
/// perhaps 30 guessable bits, and an unsalted commitment to it is one anyone can
/// confirm by guessing (SPEC §7.2).
#[must_use]
pub fn memory_leaf(salt: &[u8; 32], canonical_bytes: &[u8]) -> Hash32 {
    leaf(LeafKind::Memory, salt, canonical_bytes)
}

/// The metadata leaf, which every day has even when it is empty.
///
/// Its presence is why an empty day still produces a non-empty tree, and
/// therefore why an empty day can still seal and advance `seq` (SPEC §3.4).
#[must_use]
pub fn meta_leaf(seq: u64, date: NaiveDate, tz: &Tz, memory_count: u32) -> Hash32 {
    leaf(
        LeafKind::Meta,
        // The metadata leaf is not secret — it commits to public structure — so
        // it takes a zero salt rather than pretending to be blinded.
        &[0u8; 32],
        &[
            seq.to_be_bytes().as_slice(),
            date.to_string().as_bytes(),
            tz.name().as_bytes(),
            memory_count.to_be_bytes().as_slice(),
        ]
        .concat(),
    )
}

/// The Merkle root over one window's leaves.
///
/// # Errors
///
/// Returns [`Error::Core`](crate::Error::Core) if the leaf set is empty or
/// contains duplicates.
pub fn root(leaves: Vec<Hash32>) -> crate::Result<Hash32> {
    Ok(MerkleTree::build(leaves)?.root())
}

/// One chain link.
///
/// `tz` is in the preimage as its IANA name, so a day sealed in Bangkok and a
/// day sealed in Berlin are distinguishable even at the same instant.
#[must_use]
pub fn link(prev: Hash32, root: Hash32, seq: u64, date: NaiveDate, tz: &Tz) -> Hash32 {
    tagged_hash_parts(
        Tag::Link,
        &[
            prev.as_bytes(),
            root.as_bytes(),
            &seq.to_be_bytes(),
            date.to_string().as_bytes(),
            tz.name().as_bytes(),
        ],
    )
}

/// Builds an inclusion proof for one leaf.
///
/// # Errors
///
/// Returns [`Error::Core`](crate::Error::Core) if the leaf set is malformed.
pub fn inclusion_proof(leaves: Vec<Hash32>, target: Hash32) -> crate::Result<Option<MerkleProof>> {
    Ok(MerkleTree::build(leaves)?.prove(target))
}

/// Verifies an inclusion proof against a root.
#[must_use]
pub fn verify_leaf(proof: &MerkleProof, root: Hash32) -> bool {
    verify_inclusion(proof, root)
}

/// The minimum needed to verify one link, without the footage content.
///
/// A third party can be handed a run of these and check chain integrity while
/// learning nothing beyond how many days there were and when.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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

/// Recomputes every link over a run of records.
///
/// The core of `ghostr verify`. Reports the *first* bad sequence, because every
/// link after a break also fails and listing them all buries the one that
/// matters.
///
/// # Errors
///
/// Returns [`Error::ChainBroken`](crate::Error::ChainBroken) if a link does not
/// recompute, or [`Error::ChainGap`](crate::Error::ChainGap) if a sequence is
/// skipped.
pub fn verify_run(genesis_link: Hash32, records: &[ChainRecord]) -> crate::Result<()> {
    let mut expected_prev = genesis_link;
    let mut expected_seq = 1u64;

    for record in records {
        if record.seq != expected_seq {
            return Err(crate::Error::ChainGap {
                previous: expected_seq.saturating_sub(1),
                next: record.seq,
            });
        }
        // Check the stored parent before recomputing, so a spliced-out day is
        // reported as the break it is rather than as a hash mismatch.
        if record.prev_link != expected_prev {
            return Err(crate::Error::ChainBroken { seq: record.seq });
        }
        let recomputed = link(
            record.prev_link,
            record.root,
            record.seq,
            record.date,
            &record.tz,
        );
        if recomputed != record.link {
            return Err(crate::Error::ChainBroken { seq: record.seq });
        }
        expected_prev = record.link;
        expected_seq += 1;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tz() -> Tz {
        chrono_tz::UTC
    }

    fn date(n: u32) -> NaiveDate {
        NaiveDate::from_ymd_opt(2026, 8, n).expect("valid date")
    }

    fn build_chain(days: u32) -> (Hash32, Vec<ChainRecord>) {
        let identity = PublicKey::from_bytes([1u8; 32]);
        let chain_id = ChainId::new(1, [0u8; 10]);
        let g = genesis(&identity, chain_id, Timestamp::new(0, 0));

        let mut records = Vec::new();
        let mut prev = g;
        for i in 1..=days {
            let seq = u64::from(i);
            let root = root(vec![
                meta_leaf(seq, date(i), &tz(), 1),
                memory_leaf(&[u8::try_from(i).unwrap_or(0); 32], b"note"),
            ])
            .expect("root");
            let l = link(prev, root, seq, date(i), &tz());
            records.push(ChainRecord {
                seq,
                date: date(i),
                tz: tz(),
                root,
                prev_link: prev,
                link: l,
            });
            prev = l;
        }
        (g, records)
    }

    #[test]
    fn a_well_formed_chain_verifies() {
        let (g, records) = build_chain(5);
        assert!(verify_run(g, &records).is_ok());
    }

    #[test]
    fn an_empty_chain_verifies() {
        let (g, _) = build_chain(0);
        assert!(verify_run(g, &[]).is_ok());
    }

    /// Tampering with day 3 must be reported at day 3, not at the tip.
    #[test]
    fn tampering_is_reported_at_the_first_bad_sequence() {
        let (g, mut records) = build_chain(5);
        records[2].root = Hash32::from_bytes([9u8; 32]);
        match verify_run(g, &records) {
            Err(crate::Error::ChainBroken { seq }) => assert_eq!(seq, 3),
            other => panic!("expected ChainBroken at seq 3, got {other:?}"),
        }
    }

    #[test]
    fn removing_a_day_is_detected_as_a_gap() {
        let (g, mut records) = build_chain(5);
        records.remove(2);
        assert!(matches!(
            verify_run(g, &records),
            Err(crate::Error::ChainGap { .. })
        ));
    }

    /// Splicing out a day and renumbering the rest must still fail: the parent
    /// link no longer matches even though the sequence is contiguous.
    #[test]
    fn a_spliced_and_renumbered_chain_is_detected() {
        let (g, mut records) = build_chain(5);
        records.remove(2);
        for (i, r) in records.iter_mut().enumerate() {
            r.seq = u64::try_from(i).unwrap_or(0) + 1;
        }
        assert!(matches!(
            verify_run(g, &records),
            Err(crate::Error::ChainBroken { seq: 3 })
        ));
    }

    #[test]
    fn a_different_genesis_invalidates_the_whole_chain() {
        let (_, records) = build_chain(3);
        let other = Hash32::from_bytes([7u8; 32]);
        assert!(matches!(
            verify_run(other, &records),
            Err(crate::Error::ChainBroken { seq: 1 })
        ));
    }

    #[test]
    fn the_genesis_link_binds_identity_and_chain_id() {
        let a = genesis(
            &PublicKey::from_bytes([1u8; 32]),
            ChainId::new(1, [0u8; 10]),
            Timestamp::new(0, 0),
        );
        let b = genesis(
            &PublicKey::from_bytes([2u8; 32]),
            ChainId::new(1, [0u8; 10]),
            Timestamp::new(0, 0),
        );
        let c = genesis(
            &PublicKey::from_bytes([1u8; 32]),
            ChainId::new(2, [1u8; 10]),
            Timestamp::new(0, 0),
        );
        assert_ne!(a, b, "a different identity must yield a different genesis");
        assert_ne!(a, c, "a different chain id must yield a different genesis");
    }

    #[test]
    fn the_link_preimage_covers_seq_date_and_zone() {
        let prev = Hash32::from_bytes([1u8; 32]);
        let r = Hash32::from_bytes([2u8; 32]);
        let base = link(prev, r, 1, date(1), &tz());
        assert_ne!(base, link(prev, r, 2, date(1), &tz()));
        assert_ne!(base, link(prev, r, 1, date(2), &tz()));
        let bangkok: Tz = "Asia/Bangkok".parse().expect("zone");
        assert_ne!(base, link(prev, r, 1, date(1), &bangkok));
    }

    /// Crypto-shredding must not break the chain: the leaf stays, so the root
    /// and every link after it still recompute (SPEC Q6).
    #[test]
    fn shredding_content_leaves_the_chain_verifiable() {
        let identity = PublicKey::from_bytes([1u8; 32]);
        let g = genesis(&identity, ChainId::new(1, [0u8; 10]), Timestamp::new(0, 0));
        let secret_leaf = memory_leaf(&[5u8; 32], b"met Nan at the tea shop");
        let leaves = vec![meta_leaf(1, date(1), &tz(), 1), secret_leaf];
        let r = root(leaves).expect("root");
        let l = link(g, r, 1, date(1), &tz());

        // The content and salt are gone; only the leaf digest survives, and the
        // link still recomputes from it.
        let record = ChainRecord {
            seq: 1,
            date: date(1),
            tz: tz(),
            root: r,
            prev_link: g,
            link: l,
        };
        assert!(verify_run(g, &[record]).is_ok());
    }
}
