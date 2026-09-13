//! The public surface: the manifest that vouches for a ghost, and its
//! revocation.
//!
//! Everything else this vault publishes is ciphertext addressed to itself. This
//! module is the exception and the reason the exception exists: a
//! [`GhostManifest`] is plaintext, world-readable, and signed by the *identity*
//! key rather than the data key, because its entire job is to let a stranger
//! check that a particular ghost pubkey is one this person vouches for
//! (SPEC §8.2).
//!
//! # Why publishing this does not violate I9
//!
//! I9 says nothing published to a relay contains plaintext identity data, and
//! §9.1 says kind 31780 is plaintext JSON and must be readable. Both are in the
//! spec; SPEC §14 Q27 is where that contradiction is written down rather than
//! resolved in a function body. This module proceeds under Q27's recommended
//! reading — I9 protects *corpus* plaintext, and a key the user is deliberately
//! vouching for is the artifact rather than a leak — and makes it checkable
//! instead of assumed: [`tests::no_public_field_is_derived_from_the_corpus`]
//! asserts every field of every public payload is a key, a hash, a count, or a
//! value the user typed.
//!
//! If a human answers Q27 the other way, that test is what fails, and the
//! feature is what has to change. That is the point of writing it as a test
//! rather than a comment.

use ghostr_core::identity::{Account, GhostStatus};
use ghostr_crypto::{Keystore, Signer};
use ghostr_nostr::client::{PublishScope, RelayClient};
use ghostr_nostr::codec;
use ghostr_nostr::kinds::Kind;
use ghostr_nostr::payload::{GhostManifest, GhostPolicy, RevocationNotice, RevocationTarget};

use crate::engine::Engine;

/// Builds the manifest this vault would publish right now.
///
/// Pure with respect to the network: it reads the vault and returns the
/// document. Separated from publishing so `ghostr ghost show` can print exactly
/// what `ghostr ghost publish` would send — a preview that differs from the
/// thing previewed is worse than none.
///
/// # Errors
///
/// Returns an error if the vault is locked or its chain metadata is missing.
pub fn manifest(engine: &Engine, status: GhostStatus) -> crate::Result<GhostManifest> {
    let ghost_pubkey = engine.keystore().account_pubkey(Account::Ghost)?;
    let chain_id = engine.store().chain_id()?;
    let genesis_link = engine.store().genesis_link()?;

    // The ordinal only. §9.1's payload comment is explicit that the content
    // hash stays out: publishing it would let an observer watching the relay
    // detect exactly when the persona changed, which is a fact about the user's
    // life rather than about the ghost's identity.
    let persona_ordinal = crate::ops::persona_head(engine)?.map_or(0, |p| p.version.ordinal);

    let policy = engine.config()?.ghost_policy();

    Ok(GhostManifest {
        chain_id,
        ghost_pubkey,
        created_at: engine.store().created_at()?,
        persona_ordinal,
        genesis_link,
        chain_version: ghostr_core::footage::CommitmentVersion::current().as_u16(),
        status,
        policy,
        // A vault with no id predates the field. Empty rather than minted here:
        // an id that appears when a manifest is first published is a different
        // id on every machine that publishes one, which would make the
        // manifest's whole fork claim noise (SPEC §14 Q29).
        sealing_device: engine.device_id()?.unwrap_or_default(),
    })
}

/// Publishes the manifest, making the ghost binding checkable by a stranger.
///
/// # Errors
///
/// Returns an error if the vault is locked, the `manifest` scope is not
/// enabled, or every relay refused.
pub async fn publish_manifest(
    engine: &Engine,
    relays: &dyn RelayClient,
    status: GhostStatus,
) -> crate::Result<GhostManifest> {
    publish_manifest_under(engine, relays, status, PublishScope::Manifest).await
}

/// The same, under a caller-chosen scope.
///
/// Exists for one caller: [`revoke`]. §8.2 says revocation *is* a manifest
/// update, so the update is part of the revocation and travels under
/// `PublishScope::Revocation` — the one scope that is always permitted.
///
/// Publishing it under `Manifest` instead meant a vault that had never enabled
/// manifest publishing could not revoke, which inverts the exemption exactly:
/// the person most likely to have publishing switched off is the person who
/// never wanted their ghost public, and they are no less entitled to say it no
/// longer speaks for them. Worse, the notice would have published while the
/// binding stayed `Active`, leaving a reader with two documents that disagree
/// and no rule for which wins.
///
/// Private, so no caller outside this module can publish a manifest under a
/// scope of its choosing and route around the gate.
async fn publish_manifest_under(
    engine: &Engine,
    relays: &dyn RelayClient,
    status: GhostStatus,
    scope: PublishScope,
) -> crate::Result<GhostManifest> {
    let payload = manifest(engine, status)?;
    let key = engine.keystore().key_ref(Account::Identity)?;

    // The `d` tag is the chain id, so republishing replaces rather than
    // accumulates: NIP-01 addressable events are keyed on
    // `(pubkey, kind, d-tag)`, and a manifest whose status changed must
    // *supersede* the old one. A per-publish identifier would leave a revoked
    // ghost's Active manifest sitting on the relay beside its revocation, and a
    // reader picking either would be right (SPEC §9.1).
    let identifier = payload.chain_id.as_uuid().to_string();

    let event = codec::encode(
        engine.keystore(),
        key,
        Kind::GhostManifest,
        &identifier,
        // Not jittered, unlike footage. A manifest is a deliberate public
        // statement whose timing the user chose; hiding when it was made would
        // obscure the ordering of a revocation against what it revokes, which
        // is the one thing a reader needs to get right.
        engine.now().utc_millis().unsigned_abs() / 1000,
        &payload,
        // Unused: kind 31780 is not encrypted. Passed because `encode` takes
        // one nonce for every kind, and drawing a real one keeps the call site
        // from implying this kind could be made private by changing a flag.
        engine.rng().salt(),
    )
    .await?;

    let sig = engine.keystore().sign_event(key, &event).await?;
    let signed = ghostr_crypto::event::SignedEvent {
        id: event.id(),
        event,
        sig,
    };

    crate::sync::publish_logged(engine, relays, signed, scope, "ghost_manifest", false).await?;

    Ok(payload)
}

/// Revokes the ghost: a manifest update, plus a standalone notice.
///
/// Two events, deliberately. §8.2 says revocation *is* a manifest update with
/// `status: Revoked`, and that is what a reader resolving the ghost binding
/// will see — but a reader who already cached the manifest has no reason to
/// re-fetch it. The kind-31788 notice is the push half, and it is the one that
/// travels: it is a new event rather than a replacement, so a relay serves it
/// to anyone subscribed (SPEC §9.1).
///
/// Both are attempted and the manifest goes first. If the notice fails, the
/// binding still reads as revoked to anyone who looks; if the manifest failed
/// and only the notice landed, a reader resolving the binding would find an
/// Active ghost contradicted by a notice, and there is no rule saying which
/// wins.
///
/// # Errors
///
/// Returns an error if the vault is locked or the manifest update failed.
/// A failed *notice* is reported in the return value rather than as an error:
/// the revocation has taken effect in the place that defines it.
pub async fn revoke(
    engine: &Engine,
    relays: &dyn RelayClient,
    reason: &str,
) -> crate::Result<Revocation> {
    let manifest = publish_manifest_under(
        engine,
        relays,
        GhostStatus::Revoked,
        PublishScope::Revocation,
    )
    .await?;

    let notice = RevocationNotice {
        target: RevocationTarget::GhostKey,
        pubkey: manifest.ghost_pubkey,
        revoked_at: engine.now(),
        // The user's own words, published verbatim. Not drawn from the corpus
        // and not summarised by a model: this is the one field of a public
        // document whose content a person chose, and rewriting it would make
        // the vault speak for them in the document that says who speaks for
        // them.
        reason: reason.to_owned(),
        // No replacement named. Deriving a new ghost key is a separate act
        // with its own manifest, and naming a successor that does not exist
        // yet would publish a binding to a key nothing has vouched for.
        replacement: None,
    };

    let key = engine.keystore().key_ref(Account::Identity)?;
    let identifier = manifest.ghost_pubkey.to_hex();
    let event = codec::encode(
        engine.keystore(),
        key,
        Kind::RevocationNotice,
        &identifier,
        engine.now().utc_millis().unsigned_abs() / 1000,
        &notice,
        engine.rng().salt(),
    )
    .await?;
    let sig = engine.keystore().sign_event(key, &event).await?;
    let signed = ghostr_crypto::event::SignedEvent {
        id: event.id(),
        event,
        sig,
    };

    // `PublishScope::Revocation` is always permitted, unlike every other scope.
    // A revocation a user cannot publish because they turned publishing off is
    // a revocation that does not happen, and the moment someone needs one is
    // not the moment to make them edit a config file.
    let notice_published = crate::sync::publish_logged(
        engine,
        relays,
        signed,
        PublishScope::Revocation,
        "revocation_notice",
        false,
    )
    .await
    .is_ok();

    Ok(Revocation {
        manifest,
        notice_published,
    })
}

/// What a revocation achieved.
#[derive(Debug, Clone)]
pub struct Revocation {
    /// The manifest as published, now `Revoked`.
    pub manifest: GhostManifest,
    /// Whether the standalone kind-31788 notice also reached a relay.
    ///
    /// A `false` here is not a failed revocation: the binding reads as revoked
    /// to anyone who resolves it. It means nobody will be *told* without
    /// looking, which the caller should say out loud rather than swallow.
    pub notice_published: bool,
}

/// The policy a config expresses.
impl crate::config::Config {
    /// What this vault has told the world its ghost may do.
    ///
    /// Derived from the publish scopes rather than configured twice. The two
    /// would otherwise be able to disagree — a manifest promising the ghost
    /// will not post, beside a vault whose `ghost_notes` scope is on — and a
    /// public document contradicted by local config is worse than no document,
    /// because a reader has no way to see the contradiction.
    #[must_use]
    pub fn ghost_policy(&self) -> GhostPolicy {
        let scopes = self.enabled_scopes();
        GhostPolicy {
            may_publish_notes: scopes.contains(&PublishScope::GhostNotes),
            // Replying is a strict subset of posting and has no scope of its
            // own yet. Reported as off rather than inferred from
            // `may_publish_notes`: claiming the ghost may reply when nothing
            // can make it reply would be the manifest promising a capability
            // that does not exist.
            may_reply: false,
            publishes_fidelity: scopes.contains(&PublishScope::Fidelity),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Nothing in a public payload comes from the corpus (SPEC §14 Q27).
    ///
    /// This module publishes plaintext, which I9 reads as forbidden and §9.1
    /// reads as required. Q27 recommends the narrow reading — I9 protects
    /// *corpus* plaintext — and this is what holds that reading to account
    /// instead of letting it be an assumption in a doc comment.
    ///
    /// Asserted over the serialised JSON rather than the struct, because that
    /// is what actually leaves: a field added later reaches the relay whether
    /// or not anyone remembered this test exists, and the serialised form is
    /// where it shows up.
    ///
    /// If a human answers Q27 the other way, this is the test that fails and
    /// the feature is what changes. That is the point of writing it as a test.
    #[test]
    fn no_public_field_is_derived_from_the_corpus() {
        use ghostr_core::hash::{Tag, tagged_hash};
        use ghostr_core::identity::PublicKey;

        let manifest = GhostManifest {
            chain_id: ghostr_core::ids::ChainId::new(1_700_000_000_000, [7; 10]),
            ghost_pubkey: PublicKey::from_bytes([3; 32]),
            created_at: ghostr_core::time::Timestamp::new(1_700_000_000_000, 0),
            persona_ordinal: 12,
            genesis_link: tagged_hash(Tag::Genesis, b"g"),
            chain_version: 2,
            status: GhostStatus::Active,
            policy: GhostPolicy::default(),
            sealing_device: "0011223344556677".to_owned(),
        };

        let json = serde_json::to_value(&manifest).expect("serialise");
        let object = json.as_object().expect("a manifest is an object");

        // Every field, named. A new one fails here rather than reaching a
        // relay, which is the whole reason this is a list and not a loop over
        // whatever happens to be present.
        const ALLOWED: [&str; 9] = [
            "chain_id",        // an opaque UUID
            "ghost_pubkey",    // a public key, the artifact itself
            "created_at",      // when the chain started
            "persona_ordinal", // a counter — deliberately not the content hash
            "genesis_link",    // a hash
            "chain_version",   // a scheme number
            "status",          // an enum the user set
            "policy",          // booleans the user set
            "sealing_device",  // random bytes, not derived from the seed
        ];
        for key in object.keys() {
            assert!(
                ALLOWED.contains(&key.as_str()),
                "`{key}` is published in plaintext and nobody decided it could be"
            );
        }
        assert_eq!(
            object.len(),
            ALLOWED.len(),
            "a field named in ALLOWED is no longer published, so the list is stale"
        );

        // The one that would be easy to add and expensive to undo. §9.1 keeps
        // the persona *content hash* out on purpose: an observer watching a
        // relay could otherwise tell exactly when the user's persona changed,
        // which is a fact about their life rather than about the ghost.
        assert!(
            !object.contains_key("persona_version") && !object.contains_key("persona_content"),
            "the persona content hash reached a public document"
        );
    }

    /// A fresh vault's ghost may do nothing.
    ///
    /// `GhostPolicy::default()` is all-off and this checks the *derived* policy
    /// agrees, which is a different claim: the manifest reports what the
    /// vault's scopes actually permit, so a default that said otherwise would
    /// be a public document contradicted by local configuration.
    #[test]
    fn a_fresh_vault_publishes_a_ghost_that_may_do_nothing() {
        let config = crate::config::Config::default();
        assert_eq!(config.ghost_policy(), GhostPolicy::default());
        assert!(!config.ghost_policy().may_publish_notes);
        assert!(!config.ghost_policy().publishes_fidelity);
    }

    /// The policy tracks the scopes rather than being a second switch.
    ///
    /// Without this the test above passes because the policy is a constant.
    #[test]
    fn enabling_a_scope_changes_what_the_manifest_promises() {
        let with = |scope: &str| crate::config::Config {
            publish_scopes: vec![scope.to_owned()],
            ..crate::config::Config::default()
        };

        let notes = with("ghost_notes").ghost_policy();
        assert!(notes.may_publish_notes);
        assert!(!notes.publishes_fidelity, "one scope enabled two promises");

        let fidelity = with("fidelity").ghost_policy();
        assert!(fidelity.publishes_fidelity);
        assert!(!fidelity.may_publish_notes);
    }

    /// The chain version numbers are frozen.
    ///
    /// They go into permanent public documents telling a reader which rules to
    /// verify under. Renumbering one makes every manifest already on a relay
    /// describe the wrong scheme, and there is no way to recall it.
    #[test]
    fn published_chain_version_numbers_are_frozen() {
        use ghostr_core::footage::CommitmentVersion;

        assert_eq!(CommitmentVersion::MemoriesOnly.as_u16(), 1);
        assert_eq!(CommitmentVersion::WithQuests.as_u16(), 2);
        // Not zero: zero is reserved for "this build cannot name the scheme",
        // which has to stay distinguishable from a real answer.
        assert_ne!(CommitmentVersion::current().as_u16(), 0);
    }
}
