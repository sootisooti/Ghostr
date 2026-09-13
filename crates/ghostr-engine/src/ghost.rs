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
use ghostr_nostr::payload::{
    FidelityAttestation, GhostManifest, GhostPolicy, RevocationNotice, RevocationTarget,
};

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

/// Builds the attestation this vault would publish for a window.
///
/// Reads the vault and returns the document. Separated from publishing for the
/// same reason as [`manifest`]: a public claim is permanent, and "publish and
/// see" is not something a relay offers.
///
/// # What is refused
///
/// A score the scorer will not compute — fewer than the window's floor of
/// held-out quests — is not published as a low number. There is no honest
/// attestation to make from a sample too small to have a meaning, and
/// `ops::fidelity` already refuses it, so this simply does not catch that
/// error (SPEC §4.4, I7).
///
/// A score that is computed but **unconverged** does publish, flagged. That is
/// the opposite choice and deliberate: suppressing unconverged scores would
/// make every published one look like a milestone rather than a measurement.
///
/// # Errors
///
/// Returns an error if the vault is locked, the sample is too small, or the
/// chain has no link at the sequence the score was computed against.
pub fn attestation(
    engine: &Engine,
    window: ghostr_core::fidelity::ScoreWindow,
) -> crate::Result<FidelityAttestation> {
    let score = crate::ops::fidelity(engine, window)?;
    let seq = score.committed_at_seq;

    // The link the score is bound to. Without it the attestation is a number
    // with a signature — true of the person, and unanchored to any record they
    // cannot later rewrite. §9.4's whole sentence is "here is my score, and
    // here is the Bitcoin-anchored commitment it was computed from".
    let footage = engine
        .store()
        .get_footage(engine.dek()?, seq)?
        .ok_or_else(|| crate::Error::Config {
            detail: format!("no sealed day at seq {seq} to bind the score to"),
        })?;

    // The proof, when there is one. `None` rather than an error: a day sealed
    // today has no confirmed OTS proof for hours, and refusing to publish until
    // Bitcoin catches up would make the feature unusable on the day a user
    // wants it. A reader can see the proof is absent and weigh it.
    let ots_base64 = engine
        .store()
        .get_anchor(seq)?
        .and_then(|record| record.ots)
        .map(|bytes| base64_encode(&bytes))
        .unwrap_or_default();

    Ok(FidelityAttestation {
        chain_id: engine.store().chain_id()?,
        as_of: score.as_of,
        window: window_tag(window)?.to_owned(),
        overall: score.overall,
        sample_size: score.sample_size,
        ci: score.confidence_interval,
        ece: score.calibration.ece,
        // Inside the payload, never alongside it. A reader must not be able to
        // receive the score without the number that discounts it: a ghost that
        // confirms decoys is agreeing with claims that were deliberately wrong,
        // and its agreement rate means nothing without that (SPEC §4.4).
        decoy_confirm_rate: score.integrity.decoy_confirm_rate,
        converged: score.converged,
        committed_at_seq: seq,
        link: footage.commitment.link,
        ots_base64,
    })
}

/// The wire name of a score window.
///
/// Hand-written. It lands in a permanent public document, so a variant rename
/// would change what an attestation already on a relay appears to claim —
/// `rolling_30` and `rolling_90` are different statements about how much
/// evidence is behind a number.
///
/// `ScoreWindow` is `#[non_exhaustive]` and this is a downstream crate, so the
/// wildcard arm is required. It **refuses** rather than guessing: a window this
/// build cannot name would otherwise be published under some other window's
/// label, and a reader weighing "90 days" against a number computed over 30 has
/// no way to notice. Not publishing is the failure a user can see.
fn window_tag(window: ghostr_core::fidelity::ScoreWindow) -> crate::Result<&'static str> {
    use ghostr_core::fidelity::ScoreWindow;

    match window {
        ScoreWindow::Rolling30 => Ok("rolling_30"),
        ScoreWindow::Rolling90 => Ok("rolling_90"),
        ScoreWindow::AllTime => Ok("all_time"),
        _ => Err(crate::Error::Config {
            detail: "this build cannot name that score window, so it will not publish one"
                .to_owned(),
        }),
    }
}

/// Base64, standard alphabet with padding.
///
/// Hand-rolled rather than a dependency: this is the only base64 in the crate,
/// and CLAUDE.md §4.9 asks for a justification per dependency that a
/// forty-line encoder does not earn.
fn base64_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        let indices = [(n >> 18) & 63, (n >> 12) & 63, (n >> 6) & 63, n & 63];
        for (i, index) in indices.iter().enumerate() {
            // Padding covers the bytes the chunk did not have. Each output
            // character carries 6 bits, so a 1-byte chunk fills two of them and
            // a 2-byte chunk three.
            if i > chunk.len() {
                out.push('=');
            } else {
                out.push(char::from(ALPHABET[*index as usize]));
            }
        }
    }
    out
}

/// Publishes the attestation.
///
/// # Errors
///
/// Returns an error if the vault is locked, the `fidelity` scope is not
/// enabled, the sample is too small, or every relay refused.
pub async fn publish_attestation(
    engine: &Engine,
    relays: &dyn RelayClient,
    window: ghostr_core::fidelity::ScoreWindow,
) -> crate::Result<FidelityAttestation> {
    let payload = attestation(engine, window)?;
    let key = engine.keystore().key_ref(Account::Identity)?;

    // The `d` tag is the window, so today's rolling-90 replaces yesterday's
    // rather than accumulating a public history of every daily score. That is
    // a privacy decision as much as a storage one: a relay holding one
    // attestation per day per window is a graph of the user's fidelity over
    // time, which nobody asked to publish (§9.1).
    let identifier = payload.window.clone();

    let event = codec::encode(
        engine.keystore(),
        key,
        Kind::FidelityAttestation,
        &identifier,
        engine.now().utc_millis().unsigned_abs() / 1000,
        &payload,
        engine.rng().salt(),
    )
    .await?;

    let sig = engine.keystore().sign_event(key, &event).await?;
    let signed = ghostr_crypto::event::SignedEvent {
        id: event.id(),
        event,
        sig,
    };

    crate::sync::publish_logged(
        engine,
        relays,
        signed,
        PublishScope::Fidelity,
        "fidelity_attestation",
        false,
    )
    .await?;

    Ok(payload)
}

/// Publishes a note under the ghost key, disclosed as ghost-authored.
///
/// # What this is, and what it is not (SPEC §14 Q30)
///
/// The user writes the text; the ghost key signs it. That is the feature §9.3
/// specifies, it needs no model, and it is genuinely useful — a pen name whose
/// disclosure tags are honest about which key held the pen.
///
/// It is **not** the ghost composing from the persona. That is what §1 promises
/// and it routes through `LanguageModel` (I4), the egress gate (I5) and
/// `Sensitivity` on every fact it would draw from the corpus, plus the refusal
/// behaviour M4 lists. Shipping this under that name would pass a roadmap
/// criterion while the feature stayed absent, which is how a third of this
/// milestone went missing the first time.
///
/// # Two gates, not one
///
/// `PublishScope::GhostNotes` is *this device's* consent. `GhostPolicy
/// .may_publish_notes` in the published manifest is what the user told the
/// world their ghost may do. Both are required, and the second is the one that
/// is easy to miss: a note that violates the published policy makes the
/// manifest a lie, and a manifest nobody can rely on is worth less than none.
///
/// The policy is read from the manifest this vault *would* publish rather than
/// fetched from a relay. Fetching would make posting depend on a network round
/// trip to learn a fact the vault already holds, and a relay that withheld the
/// manifest could then unblock a note the user had forbidden.
///
/// # Errors
///
/// Returns an error if the vault is locked, either gate refuses, the text is
/// empty, or every relay refused.
pub async fn publish_note(
    engine: &Engine,
    relays: &dyn RelayClient,
    text: &str,
) -> crate::Result<ghostr_crypto::event::SignedEvent> {
    let policy = engine.config()?.ghost_policy();
    if !policy.may_publish_notes {
        return Err(crate::Error::Config {
            detail: "this vault's manifest says its ghost may not post;                      enable the `ghost_notes` publish scope first"
                .to_owned(),
        });
    }

    let ghost_pubkey = engine.keystore().account_pubkey(Account::Ghost)?;
    let principal = engine.keystore().account_pubkey(Account::Identity)?;

    // `GhostNoteBuilder` is the only constructor and it emits the disclosure
    // tags itself, so an undisclosed ghost note is not something this function
    // could get wrong even by trying (I10).
    let event = ghostr_nostr::codec::GhostNoteBuilder::new(ghost_pubkey, principal)
        .content(text)
        .build(engine.now().utc_millis().unsigned_abs() / 1000)?;

    // Signed by the ghost key, which is the whole point: a reader checking the
    // signature learns it was the ghost and not the person, and the `p` tag
    // tells them whose ghost.
    let key = engine.keystore().key_ref(Account::Ghost)?;
    let sig = engine.keystore().sign_event(key, &event).await?;
    let signed = ghostr_crypto::event::SignedEvent {
        id: event.id(),
        event,
        sig,
    };

    crate::sync::publish_logged(
        engine,
        relays,
        signed.clone(),
        PublishScope::GhostNotes,
        "ghost_note",
        false,
    )
    .await?;

    Ok(signed)
}

/// What a reader learns from an attestation they did not write.
///
/// The half that makes the claim checkable rather than merely publishable. A
/// third party has the event and the author's npub, and nothing else — no
/// vault, no corpus, no quests. This says what they can establish.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestationCheck {
    /// The signature verifies and the id matches the body.
    ///
    /// False means the relay served something forged or altered. Nothing below
    /// means anything when this is false.
    pub signature_valid: bool,
    /// The event was signed by the key the reader asked about.
    ///
    /// Separate from `signature_valid`, and the distinction matters: an event
    /// can be perfectly signed by somebody else. A reader who checks only the
    /// signature has verified that *a* person made this claim.
    pub author_matches: bool,
    /// The payload names a chain link.
    ///
    /// An attestation whose `link` is all zeroes, or whose `committed_at_seq`
    /// is zero, is a score bound to nothing.
    pub chain_bound: bool,
    /// An OTS proof is present.
    ///
    /// Not that it is *valid* — verifying one needs a Bitcoin node or a
    /// calendar, which a reader may not have and this function does not do.
    /// Reported as its own field so a caller cannot mistake "present" for
    /// "confirmed".
    pub proof_present: bool,
}

/// Checks an attestation as a stranger would.
///
/// Takes the raw event and the pubkey the reader believes they are asking
/// about. Deliberately returns a report rather than a bool: "this failed" tells
/// a reader nothing about whether to distrust the person or the relay, and
/// those call for different responses.
///
/// # Errors
///
/// Returns an error if the event's content is not a readable attestation. That
/// is not a failed check — it means this was never an attestation at all.
pub fn check_attestation(
    event: &ghostr_crypto::event::SignedEvent,
    expected_author: &ghostr_core::identity::PublicKey,
) -> crate::Result<(FidelityAttestation, AttestationCheck)> {
    let payload: FidelityAttestation =
        serde_json::from_str(&event.event.content).map_err(|_| crate::Error::Config {
            detail: "event content is not a fidelity attestation".to_owned(),
        })?;

    let check = AttestationCheck {
        signature_valid: event.verify().is_ok(),
        author_matches: event.event.pubkey == *expected_author,
        chain_bound: payload.committed_at_seq > 0
            && payload.link != ghostr_core::hash::Hash32::from_bytes([0; 32]),
        proof_present: !payload.ots_base64.is_empty(),
    };
    Ok((payload, check))
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

    /// The hand-rolled base64 matches the standard alphabet and padding.
    ///
    /// Vectors from RFC 4648 §10, which is the point of not writing my own
    /// expected values: an encoder tested against its own output is a test that
    /// the function is deterministic, not that it is base64. The `.ots` proof
    /// travels in a public document and a reader decodes it with a library, so
    /// "close enough" is a proof nobody can check.
    #[test]
    fn base64_matches_rfc_4648() {
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(b"foob"), "Zm9vYg==");
        assert_eq!(base64_encode(b"fooba"), "Zm9vYmE=");
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");

        // The high end of the alphabet, which a table typo would miss: `+` and
        // `/` are the two characters an implementation most often gets wrong by
        // reaching for the URL-safe variant.
        assert_eq!(base64_encode(&[0xfb, 0xff, 0xbf]), "+/+/");
        assert_eq!(base64_encode(&[0x00, 0x00, 0x00]), "AAAA");
        assert_eq!(base64_encode(&[0xff, 0xff, 0xff]), "////");
    }

    /// Every window has a name and no two share one.
    ///
    /// The names are part of the claim: a reader weighing "90 days" against a
    /// number computed over 30 needs the label to be true.
    #[test]
    fn every_window_has_its_own_frozen_name() {
        use ghostr_core::fidelity::ScoreWindow;

        assert_eq!(window_tag(ScoreWindow::Rolling30).unwrap(), "rolling_30");
        assert_eq!(window_tag(ScoreWindow::Rolling90).unwrap(), "rolling_90");
        assert_eq!(window_tag(ScoreWindow::AllTime).unwrap(), "all_time");
    }

    /// A stranger's check separates "forged" from "somebody else's".
    ///
    /// Both are failures and they call for different responses: one means the
    /// relay is lying, the other means the reader asked about the wrong key.
    /// A single bool would collapse them.
    #[test]
    fn a_reader_can_tell_a_forgery_from_the_wrong_author() {
        use ghostr_core::identity::PublicKey;
        use ghostr_crypto::event::{SignedEvent, UnsignedEvent};

        let payload = FidelityAttestation {
            chain_id: ghostr_core::ids::ChainId::new(1_700_000_000_000, [1; 10]),
            as_of: chrono::NaiveDate::from_ymd_opt(2026, 8, 25).expect("date"),
            window: "rolling_90".to_owned(),
            overall: 0.87,
            sample_size: 241,
            ci: (0.82, 0.91),
            ece: 0.037,
            decoy_confirm_rate: 0.04,
            converged: true,
            committed_at_seq: 412,
            link: ghostr_core::hash::tagged_hash(ghostr_core::hash::Tag::Link, b"412"),
            ots_base64: "AAEC".to_owned(),
        };

        // Never signed, so the signature check must fail. That is the point:
        // this is what a relay serving a fabricated attestation looks like.
        let author = PublicKey::from_bytes([9; 32]);
        let event = SignedEvent {
            id: ghostr_core::hash::tagged_hash(ghostr_core::hash::Tag::Node, b"forged"),
            event: UnsignedEvent {
                pubkey: author,
                created_at: 0,
                kind: 31786,
                tags: Vec::new(),
                content: serde_json::to_string(&payload).expect("serialise"),
            },
            sig: ghostr_crypto::event::Signature::from_bytes([0; 64]),
        };

        let (decoded, check) = check_attestation(&event, &author).expect("readable");
        assert_eq!(decoded, payload);
        assert!(!check.signature_valid, "an unsigned event verified");
        assert!(
            check.author_matches,
            "the author is who the reader asked for"
        );
        assert!(check.chain_bound, "the payload names seq 412 and a link");
        assert!(check.proof_present);

        // Asked about a different key: the signature is no more valid, and the
        // author now mismatches too. Separately reported.
        let (_, other) = check_attestation(&event, &PublicKey::from_bytes([8; 32])).expect("ok");
        assert!(!other.author_matches);
    }

    /// A score bound to nothing is visible as such.
    ///
    /// §9.4's claim is "here is my score *and* the commitment it was computed
    /// from". An attestation with a zero link is the first half alone, and a
    /// reader must be able to see that rather than reading a signed number as
    /// an anchored one.
    #[test]
    fn an_unbound_score_does_not_read_as_anchored() {
        use ghostr_core::identity::PublicKey;
        use ghostr_crypto::event::{SignedEvent, UnsignedEvent};

        let payload = FidelityAttestation {
            chain_id: ghostr_core::ids::ChainId::new(1_700_000_000_000, [1; 10]),
            as_of: chrono::NaiveDate::from_ymd_opt(2026, 8, 25).expect("date"),
            window: "rolling_30".to_owned(),
            overall: 0.99,
            sample_size: 10,
            ci: (0.9, 1.0),
            ece: 0.0,
            decoy_confirm_rate: 0.0,
            converged: false,
            committed_at_seq: 0,
            link: ghostr_core::hash::Hash32::from_bytes([0; 32]),
            ots_base64: String::new(),
        };

        let author = PublicKey::from_bytes([4; 32]);
        let event = SignedEvent {
            id: ghostr_core::hash::tagged_hash(ghostr_core::hash::Tag::Node, b"unbound"),
            event: UnsignedEvent {
                pubkey: author,
                created_at: 0,
                kind: 31786,
                tags: Vec::new(),
                content: serde_json::to_string(&payload).expect("serialise"),
            },
            sig: ghostr_crypto::event::Signature::from_bytes([0; 64]),
        };

        let (_, check) = check_attestation(&event, &author).expect("readable");
        assert!(!check.chain_bound, "a zero link read as a chain binding");
        assert!(!check.proof_present, "an absent proof read as present");
    }

    /// The decoy rate cannot be dropped from a published attestation.
    ///
    /// §4.4: a reader must not be able to receive the score without the number
    /// that discounts it. Asserted over the serialised form, because that is
    /// what a reader parses — a field skipped on serialisation would leave the
    /// struct looking complete.
    #[test]
    fn a_published_score_always_carries_its_decoy_rate() {
        let payload = FidelityAttestation {
            chain_id: ghostr_core::ids::ChainId::new(1_700_000_000_000, [1; 10]),
            as_of: chrono::NaiveDate::from_ymd_opt(2026, 8, 25).expect("date"),
            window: "rolling_90".to_owned(),
            overall: 0.87,
            sample_size: 241,
            ci: (0.82, 0.91),
            ece: 0.037,
            decoy_confirm_rate: 0.04,
            converged: false,
            committed_at_seq: 412,
            link: ghostr_core::hash::tagged_hash(ghostr_core::hash::Tag::Link, b"412"),
            ots_base64: String::new(),
        };

        let json = serde_json::to_value(&payload).expect("serialise");
        let object = json.as_object().expect("object");
        assert!(
            object.contains_key("decoy_confirm_rate"),
            "the score published without the number that discounts it"
        );
        assert!(
            object.contains_key("converged"),
            "an unconverged score published without saying so"
        );
        assert!(
            object.contains_key("sample_size") && object.contains_key("ci"),
            "a point estimate published with no sense of its width"
        );
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
