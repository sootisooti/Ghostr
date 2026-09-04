//! Publishing sealed footage to relays, and rebuilding a vault from them.
//!
//! This is where the relay transport meets the vault, and the composition root
//! is the only place that may hold both: `ghostr-nostr` knows nothing about a
//! store, and `ghostr-store` knows nothing about a network.
//!
//! # What actually goes to a relay
//!
//! Ciphertext, addressed by a key that is not the user's identity. Each sealed
//! day becomes one kind-31783 event, NIP-44 encrypted to the vault's own data
//! key and signed by it — self-encryption, so a relay stores something only this
//! vault can read, and nothing links it to the identity (I1, I9).
//!
//! # Restore is not the same as sync
//!
//! Syncing is a backup: the vault already holds the truth and the relay gets a
//! copy. Restoring is the reverse and is only meaningful on a machine that has
//! nothing — so it rebuilds from the seed, and the device it produces is a
//! **replica**, not a second sealer (SPEC §14 Q10).

use std::collections::HashSet;

use ghostr_core::footage::Footage;
use ghostr_core::identity::Account;
use ghostr_crypto::{Keystore, Signer};
use ghostr_nostr::client::{Filter, PublishScope, RelayClient};
use ghostr_nostr::kinds::Kind;
use ghostr_nostr::{codec, privacy};

use crate::engine::{DeviceRole, Engine};

/// What a sync achieved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncReport {
    /// Days published on this run.
    pub published: u64,
    /// Days a relay already had, and which were not sent again.
    pub already_present: u64,
    /// Days that failed to publish, by `seq`.
    pub failed: Vec<u64>,
    /// Days whose NIP-78 mirror was published alongside the 3178x form.
    ///
    /// Counted separately rather than folded into `published`, because the two
    /// can differ: a relay that accepts kind 30078 and refuses an unrecognised
    /// 3178x — or the reverse — leaves a day backed up in one form only, and a
    /// single number would hide which.
    pub mirrored: u64,
    /// Days published under 3178x whose mirror a relay refused, by `seq`.
    ///
    /// Not a failure of the day: the backup exists. It is a failure of the
    /// *fallback*, and a vault whose mirror is missing is one that depends on
    /// the kind block being resolvable — the assumption the mirror exists to
    /// remove (SPEC Q3).
    pub mirror_failed: Vec<u64>,
}

/// What a restore rebuilt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestoreReport {
    /// Days recovered and written to the new store.
    pub recovered: u64,
    /// Events a relay served that did not decrypt or did not belong.
    pub rejected: u64,
    /// The highest `seq` recovered, which is the tip of the restored chain.
    pub tip: Option<u64>,
}

/// How far a publish time may drift from the seal it describes.
///
/// Six hours. The moment a footage reaches a relay would otherwise say roughly
/// when the user sealed it, which is a fact about their sleep and their habits
/// rather than about the footage.
const PUBLISH_JITTER_SECS: u32 = 6 * 60 * 60;

/// The `d` tag identifying one day's footage backup.
fn footage_identifier(seq: u64) -> String {
    format!("{seq}")
}

/// Publishes every sealed day the relays do not already hold.
///
/// # Errors
///
/// Returns an error if the vault is locked, no relays are configured, or the
/// `backup` scope is not enabled. A relay that refuses one day does not fail the
/// run — the report names it.
pub async fn sync(engine: &Engine, relays: &dyn RelayClient) -> crate::Result<SyncReport> {
    let dek = engine.dek()?;
    let key = engine.keystore().key_ref(Account::Data)?;
    let data_pubkey = engine.keystore().account_pubkey(Account::Data)?;

    // What the relays already hold, asked once rather than per day: a fetch per
    // sealed day would be a request per day of the user's life.
    //
    // Both forms, and kept apart. A day whose 3178x event published but whose
    // mirror was refused is half-backed-up, and a single set would read it as
    // done and never send the missing half — the mirror would be reported
    // failed once and then never retried.
    let mut has_primary: HashSet<String> = HashSet::new();
    let mut has_mirror: HashSet<String> = HashSet::new();
    for event in relays
        .fetch(&Filter {
            authors: vec![data_pubkey],
            kinds: vec![Kind::FootageRecord],
            raw_kinds: vec![ghostr_nostr::kinds::NIP78_APP_DATA],
            ..Filter::default()
        })
        .await?
    {
        // The author is checked here rather than trusted to the filter, and
        // this is not belt-and-braces. `authors` is a *request*; a relay is free
        // to ignore it and serve whatever it likes. A relay that answered with
        // events carrying our `d` tags would make this loop skip every day as
        // "already backed up" — a vault that believes it has a backup and does
        // not, which is worse than one that knows it has none.
        if event.event.pubkey != data_pubkey {
            continue;
        }
        let Some(d_tag) = event
            .event
            .tags
            .iter()
            .find(|tag| tag.first().map(String::as_str) == Some("d"))
            .and_then(|tag| tag.get(1).cloned())
        else {
            continue;
        };
        if event.event.kind == ghostr_nostr::kinds::NIP78_APP_DATA {
            has_mirror.insert(d_tag);
        } else {
            has_primary.insert(d_tag);
        }
    }

    let mut report = SyncReport {
        published: 0,
        already_present: 0,
        failed: Vec::new(),
        mirrored: 0,
        mirror_failed: Vec::new(),
    };

    for footage in engine.store().all_footage(dek)? {
        let identifier = footage_identifier(footage.seq);
        // The `d` tag carries the seq, so a day already on a relay is skipped
        // by name rather than by re-encrypting it and comparing ciphertext —
        // which would differ every time anyway, since the nonce is fresh.
        let d_tag = format!("ghostr/v1/footage/{identifier}");
        let needs_primary = !has_primary.contains(&d_tag);
        let needs_mirror = !has_mirror.contains(&d_tag);
        if !needs_primary && !needs_mirror {
            report.already_present += 1;
            continue;
        }

        let nonce = engine.rng().salt();
        let event = codec::encode(
            engine.keystore(),
            key,
            Kind::FootageRecord,
            &identifier,
            // Publish time is jittered rather than exact: the moment a footage
            // reaches a relay would otherwise say when the user sealed it.
            privacy::jitter_created_at(
                footage.window.1.utc_millis().unsigned_abs() / 1000,
                engine.rng(),
                PUBLISH_JITTER_SECS,
            ),
            &footage,
            nonce,
        )
        .await?;

        // Built before the primary is consumed, and from the same body, so the
        // two copies cannot drift. Only one of them is anchored; a re-encode
        // here would let the unanchored one say something else.
        let mirror = codec::mirror_as_nip78(&event)?;

        if needs_primary {
            let sig = engine.keystore().sign_event(key, &event).await?;
            let signed = ghostr_crypto::event::SignedEvent {
                id: event.id(),
                event,
                sig,
            };

            match relays.publish(signed, PublishScope::Backup).await {
                Ok(_) => report.published += 1,
                Err(_) => {
                    // The mirror of a day that is not there is not worth
                    // sending: a fallback for a backup that does not exist.
                    report.failed.push(footage.seq);
                    continue;
                }
            }
        }

        if !needs_mirror {
            continue;
        }

        // Signed separately: the mirror is a different kind, so it is a
        // different event id, and one signature cannot cover both.
        let mirror_sig = engine.keystore().sign_event(key, &mirror).await?;
        let signed_mirror = ghostr_crypto::event::SignedEvent {
            id: mirror.id(),
            event: mirror,
            sig: mirror_sig,
        };
        match relays.publish(signed_mirror, PublishScope::Backup).await {
            Ok(_) => report.mirrored += 1,
            Err(_) => report.mirror_failed.push(footage.seq),
        }
    }
    Ok(report)
}

/// Rebuilds a vault's footage from relays.
///
/// The caller supplies an engine whose keystore is unlocked from the seed and
/// whose store is empty. Every event is decrypted with this vault's own data
/// key, so a relay serving somebody else's events — or its own — contributes
/// nothing.
///
/// The vault becomes a [`DeviceRole::Replica`]: it holds the history but does
/// not seal, because the machine that has been sealing all along still is
/// (SPEC §14 Q10).
///
/// # Errors
///
/// Returns an error if the vault is locked, no relays are configured, or the
/// recovered days do not form a gapless chain from 1.
pub async fn restore(engine: &Engine, relays: &dyn RelayClient) -> crate::Result<RestoreReport> {
    let dek = engine.dek()?;
    let key = engine.keystore().key_ref(Account::Data)?;
    let data_pubkey = engine.keystore().account_pubkey(Account::Data)?;

    // Both forms, in one query. The mirror is not a retry for when 3178x comes
    // back empty: a relay may hold one and not the other — it may not recognise
    // an unclaimed kind, or may have been written to by an older client — and
    // asking for both is what makes the fallback a fallback rather than a
    // second guess (SPEC Q3).
    let events = relays
        .fetch(&Filter {
            // Only our own data key. A relay is free to serve anything, and
            // without this the decrypt below would be the only thing standing
            // between a stranger's event and this vault's chain.
            authors: vec![data_pubkey],
            kinds: vec![Kind::FootageRecord],
            raw_kinds: vec![ghostr_nostr::kinds::NIP78_APP_DATA],
            ..Filter::default()
        })
        .await?;

    let mut recovered: Vec<Footage> = Vec::new();
    let mut rejected = 0_u64;
    let mut seen: std::collections::BTreeSet<u64> = std::collections::BTreeSet::new();

    for event in events {
        // Signatures were verified by the relay client; this is the second
        // check, that the event was encrypted by *this* vault. An event that
        // does not decrypt is not ours, whoever signed it.
        //
        // `decode_mirrored` accepts either kind. What it does not relax is the
        // `d` tag: kind 30078 is shared application data anyone may publish, so
        // that tag is the only thing separating this vault's footage from
        // another application's settings blob.
        match codec::decode_mirrored::<Footage>(
            engine.keystore(),
            key,
            Kind::FootageRecord,
            &event.event,
        )
        .await
        {
            // A day present in both forms is one day. The two carry identical
            // content by construction, so taking the first and counting the
            // second as neither recovered nor rejected is the honest answer:
            // nothing was wrong with it and nothing new came of it.
            Ok(footage) if seen.insert(footage.seq) => recovered.push(footage),
            Ok(_) => {}
            Err(_) => rejected += 1,
        }
    }

    recovered.sort_by_key(|footage| footage.seq);
    recovered.dedup_by_key(|footage| footage.seq);

    // A chain with a hole in it is not a chain. Restoring 1,2,4 and calling it
    // recovered would produce a vault whose `verify` fails later, far from the
    // thing that caused it — so it fails here, where the cause is visible.
    for (index, footage) in recovered.iter().enumerate() {
        let expected = u64::try_from(index).unwrap_or(u64::MAX).saturating_add(1);
        if footage.seq != expected {
            return Err(crate::Error::Config {
                detail: format!(
                    "relays hold an incomplete chain: expected seq {expected}, found {}",
                    footage.seq
                ),
            });
        }
    }

    // The chain this vault is joining is not the one `Engine::init` minted for
    // it. Genesis is `H(identity ‖ created_at ‖ chain_id)`, and a fresh vault's
    // `chain_id` and `created_at` are its own — so its genesis link is not the
    // one the recovered links were computed against, and `verify` fails at
    // seq 1. It did, on every restored vault, and the existing test did not
    // notice because it compared footage fields rather than running `verify`.
    //
    // Seq 1's `prev_link` *is* the original genesis link: that is what a chain
    // link commits to. Adopt it.
    if let Some(first) = recovered.first() {
        engine
            .store()
            .set_meta(
                ghostr_store::schema::meta_key::GENESIS_LINK,
                &first.commitment.prev_link.to_hex(),
            )
            .map_err(crate::Error::Store)?;
        // And forget the chain id, rather than keep one that no longer hashes
        // to that link. It is not recoverable from anything published today —
        // `Footage` does not carry it — and a wrong value nothing checks is
        // worse than an absent one, because the next reader believes it.
        engine
            .store()
            .clear_meta(ghostr_store::schema::meta_key::CHAIN_ID)
            .map_err(crate::Error::Store)?;
    }

    let tip = recovered.last().map(|footage| footage.seq);
    for footage in &recovered {
        let leaves = Vec::new();
        let mut nonce = [0u8; 24];
        engine.rng().fill(&mut nonce);
        // Leaves are not recoverable from a backup — they are hashes of memories
        // this device never had. The footage's own root still verifies, which is
        // what a replica needs to check the chain.
        engine.store().seal_footage(dek, footage, &leaves, nonce)?;
    }

    // Last, and only on success: a vault that failed halfway through is not a
    // replica, it is an empty vault, and marking it would strand the user.
    engine.set_device_role(DeviceRole::Replica)?;

    Ok(RestoreReport {
        recovered: u64::try_from(recovered.len()).unwrap_or(u64::MAX),
        rejected,
        tip,
    })
}
