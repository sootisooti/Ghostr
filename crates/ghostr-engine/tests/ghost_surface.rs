//! The public claim: a manifest a stranger can check, and its revocation.
//!
//! Everything else this vault sends a relay is ciphertext addressed to itself.
//! These events are the exception — plaintext, world-readable, signed by the
//! identity key — so they get their own file and their own adversary: a reader
//! who has the user's npub and nothing else, and who must be able to answer
//! "is this ghost really theirs" and "does it still speak for them".
//!
//! The relay is a double. What is under test is the engine's use of the
//! transport and the shape of what it sends; `ghostr-nostr` proves the
//! transport itself, and the scope gate has its own table test there.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::Path;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use chrono_tz::Tz;
use ghostr_core::identity::GhostStatus;
use ghostr_crypto::event::SignedEvent;
use ghostr_crypto::kdf::Argon2Params;
use ghostr_crypto::secret::SecretString;
use ghostr_engine::engine::Engine;
use ghostr_engine::ghost;
use ghostr_nostr::client::{Filter, PublishReport, PublishScope, RelayClient, Subscription};

/// A relay that keeps what it is given **and enforces scopes**.
///
/// The scope check is duplicated from `WebsocketRelayClient` deliberately. A
/// double that accepted everything would let an engine-level test claim the
/// gate holds while never exercising one, and the gate is the thing standing
/// between a fresh vault and a public statement about its owner. The real
/// client's own gate is checked by `a_scope_is_refused_unless_the_vault_enabled_it`
/// in `ghostr-nostr`, so the two cannot drift without one of them failing.
#[derive(Clone)]
struct ScopedRelay {
    stored: Arc<Mutex<Vec<SignedEvent>>>,
    enabled: Arc<std::collections::HashSet<PublishScope>>,
}

impl ScopedRelay {
    fn with(scopes: &[PublishScope]) -> Self {
        Self {
            stored: Arc::new(Mutex::new(Vec::new())),
            enabled: Arc::new(scopes.iter().copied().collect()),
        }
    }

    fn events(&self) -> Vec<SignedEvent> {
        self.stored.lock().unwrap().clone()
    }
}

#[async_trait]
impl RelayClient for ScopedRelay {
    async fn publish(
        &self,
        event: SignedEvent,
        scope: PublishScope,
    ) -> ghostr_nostr::Result<PublishReport> {
        if scope != PublishScope::Revocation && !self.enabled.contains(&scope) {
            return Err(ghostr_nostr::Error::PublishingDisabled {
                scope: format!("{scope:?}"),
            });
        }
        self.stored.lock().unwrap().push(event);
        Ok(PublishReport {
            accepted: vec!["memory".to_owned()],
            rejected: Vec::new(),
            unreachable: Vec::new(),
        })
    }

    async fn fetch(&self, _filter: &Filter) -> ghostr_nostr::Result<Vec<SignedEvent>> {
        Ok(self.stored.lock().unwrap().clone())
    }

    async fn subscribe(&self, _filter: Filter) -> ghostr_nostr::Result<Box<dyn Subscription>> {
        unreachable!("the public surface publishes rather than subscribes")
    }
}

fn vault(dir: &Path) -> Engine {
    let (engine, _) = Engine::init(
        dir,
        &SecretString::new("correct horse battery staple".to_owned()),
        Tz::UTC,
        None,
        None,
        Argon2Params {
            memory_kib: 8,
            iterations: 1,
            lanes: 1,
        },
    )
    .expect("init");
    engine
}

/// A fresh vault says nothing about itself in public.
///
/// The default scope set is empty, so this is the state every user starts in,
/// and a public statement is permanent. Asserted at the engine level rather
/// than trusting the config default, because what matters is that the publish
/// path refuses — not that a struct field is `false`.
#[tokio::test]
async fn a_manifest_is_refused_until_the_scope_is_enabled() {
    let tmp = tempfile::tempdir().unwrap();
    let engine = vault(tmp.path());
    let relay = ScopedRelay::with(&[]);

    let err = ghost::publish_manifest(&engine, &relay, GhostStatus::Active)
        .await
        .expect_err("a fresh vault must not publish a manifest");
    assert!(
        format!("{err}").to_lowercase().contains("disabl"),
        "refused for the wrong reason: {err}"
    );
    assert!(
        relay.events().is_empty(),
        "the event reached the relay despite being refused"
    );
}

/// And with the scope on, it publishes — and a reader can check it.
///
/// The other half, or the test above passes for a vault that can never publish
/// anything at all.
#[tokio::test]
async fn a_published_manifest_verifies_and_names_the_ghost() {
    let tmp = tempfile::tempdir().unwrap();
    let engine = vault(tmp.path());
    let relay = ScopedRelay::with(&[PublishScope::Manifest]);

    let published = ghost::publish_manifest(&engine, &relay, GhostStatus::Active)
        .await
        .expect("publish");

    let events = relay.events();
    assert_eq!(events.len(), 1, "expected exactly one event");
    let event = &events[0];

    // What a stranger does first: check the thing is not forged.
    event.verify().expect("a published manifest must verify");

    // Signed by the *identity* key, not the ghost key and not the data key.
    // The whole document is a statement by the person about the ghost; signed
    // by the ghost it would be the ghost vouching for itself.
    let identity = engine
        .keystore()
        .account_pubkey(ghostr_core::identity::Account::Identity)
        .unwrap();
    assert_eq!(event.event.pubkey, identity, "wrong signing account");

    assert_eq!(event.event.kind, 31780, "wrong kind");

    // Plaintext, and readable without any key. That is the point of this kind
    // and the reason SPEC §14 Q27 exists.
    let decoded: ghostr_nostr::payload::GhostManifest =
        serde_json::from_str(&event.event.content).expect("a manifest is readable plaintext");
    assert_eq!(decoded, published);

    let ghost_key = engine
        .keystore()
        .account_pubkey(ghostr_core::identity::Account::Ghost)
        .unwrap();
    assert_eq!(decoded.ghost_pubkey, ghost_key, "wrong ghost named");
    assert_ne!(
        decoded.ghost_pubkey, identity,
        "the manifest vouches for the identity key itself"
    );

    // The device id this install minted, so a second machine sealing the same
    // chain is detectable (SPEC §14 Q29).
    assert_eq!(
        decoded.sealing_device,
        engine.device_id().unwrap().unwrap(),
        "the manifest does not name this device"
    );
}

/// Republishing replaces rather than accumulating.
///
/// Kind 31780 is addressable, keyed on `(pubkey, kind, d-tag)`, and the `d` tag
/// is the chain id — so a status change supersedes. A per-publish identifier
/// would leave a revoked ghost's Active manifest sitting beside its revocation,
/// and a reader picking either would be right.
#[tokio::test]
async fn a_second_manifest_replaces_the_first() {
    let tmp = tempfile::tempdir().unwrap();
    let engine = vault(tmp.path());
    let relay = ScopedRelay::with(&[PublishScope::Manifest]);

    ghost::publish_manifest(&engine, &relay, GhostStatus::Active)
        .await
        .expect("publish");
    ghost::publish_manifest(&engine, &relay, GhostStatus::Suspended)
        .await
        .expect("publish");

    let events = relay.events();
    let tags: Vec<&str> = events
        .iter()
        .filter_map(|e| {
            e.event
                .tags
                .iter()
                .find(|t| t.first().map(String::as_str) == Some("d"))
                .and_then(|t| t.get(1))
                .map(String::as_str)
        })
        .collect();
    assert_eq!(tags.len(), 2);
    assert_eq!(
        tags[0], tags[1],
        "two manifests with different `d` tags do not replace each other: {tags:?}"
    );
}

/// A revocation publishes even from a vault that disabled everything.
///
/// `PublishScope::Revocation` is the one always-permitted scope, and the reason
/// is the moment it is needed: someone who has just realised their ghost key is
/// compromised should not have to find and edit a config file first.
#[tokio::test]
async fn a_revocation_publishes_with_every_scope_disabled() {
    let tmp = tempfile::tempdir().unwrap();
    let engine = vault(tmp.path());

    // Not even `manifest`. The manifest update inside `revoke` rides on the
    // revocation's exemption, which is the behaviour worth pinning: a
    // revocation that could publish its notice but not update the binding
    // would leave the binding saying Active.
    let relay = ScopedRelay::with(&[]);

    let outcome = ghost::revoke(&engine, &relay, "laptop stolen")
        .await
        .expect("a revocation must publish whatever the scopes say");

    assert_eq!(outcome.manifest.status, GhostStatus::Revoked);
    assert!(
        outcome.notice_published,
        "the standalone notice was refused"
    );

    let events = relay.events();
    assert_eq!(events.len(), 2, "expected a manifest and a notice");
    let kinds: Vec<u16> = events.iter().map(|e| e.event.kind).collect();
    assert!(kinds.contains(&31780), "no manifest update: {kinds:?}");
    assert!(kinds.contains(&31788), "no revocation notice: {kinds:?}");

    // The manifest goes first. A reader who sees the notice and then resolves
    // the binding must not find an Active ghost contradicting it, and nothing
    // says which of the two wins.
    assert_eq!(
        kinds[0], 31780,
        "the notice was published before the binding"
    );

    for event in &events {
        event.verify().expect("a revocation must verify");
    }
}

/// The reason a user gave is published as they wrote it.
///
/// The one field of a public document whose content a person chose. Summarising
/// it would make the vault speak for them in the document that says who speaks
/// for them.
#[tokio::test]
async fn a_revocation_reason_is_published_verbatim() {
    let tmp = tempfile::tempdir().unwrap();
    let engine = vault(tmp.path());
    let relay = ScopedRelay::with(&[]);

    const REASON: &str = "rotating after the laptop was stolen on the 3rd";
    ghost::revoke(&engine, &relay, REASON)
        .await
        .expect("revoke");

    let notice = relay
        .events()
        .into_iter()
        .find(|e| e.event.kind == 31788)
        .expect("a notice");
    let decoded: ghostr_nostr::payload::RevocationNotice =
        serde_json::from_str(&notice.event.content).expect("readable");

    assert_eq!(decoded.reason, REASON);
    assert_eq!(
        decoded.target,
        ghostr_nostr::payload::RevocationTarget::GhostKey
    );
    assert!(
        decoded.replacement.is_none(),
        "a successor was named that nothing has vouched for"
    );
}

/// Publishing a manifest does not make a replica a sealer.
///
/// SPEC §14 Q10 resolved that handover is manual and unbuilt, and named the
/// manifest as where the sealing device is *declared*. Declaring is not
/// granting: the field says which device the user asserts is sealing, and a
/// vault must not read its own assertion back as permission.
#[tokio::test]
async fn publishing_a_manifest_does_not_grant_sealing() {
    use ghostr_engine::engine::DeviceRole;

    let tmp = tempfile::tempdir().unwrap();
    let engine = vault(tmp.path());
    engine.set_device_role(DeviceRole::Replica).unwrap();

    let relay = ScopedRelay::with(&[PublishScope::Manifest]);
    ghost::publish_manifest(&engine, &relay, GhostStatus::Active)
        .await
        .expect("a replica may still publish a manifest");

    assert_eq!(
        engine.device_role().unwrap(),
        DeviceRole::Replica,
        "publishing a manifest promoted a replica to sealer"
    );

    let date = chrono::NaiveDate::from_ymd_opt(2026, 8, 1).unwrap();
    let err = ghostr_engine::ops::memoria(&engine, date)
        .expect_err("a replica must still refuse to seal");
    assert!(format!("{err}").contains("replica"), "{err}");
}

/// Every published event is in the egress log (I5).
///
/// The public kinds are where this matters most: what left is a plaintext claim
/// about the user, signed by their identity key, and permanent.
#[tokio::test]
async fn the_public_surface_is_audited_like_everything_else() {
    let tmp = tempfile::tempdir().unwrap();
    let engine = vault(tmp.path());
    let relay = ScopedRelay::with(&[]);

    ghost::revoke(&engine, &relay, "test")
        .await
        .expect("revoke");

    let log = engine
        .store()
        .egress_since(ghostr_core::time::Timestamp::new(0, 0))
        .expect("egress");
    assert_eq!(log.len(), 2, "a public publish went unlogged: {log:?}");

    for row in &log {
        assert_eq!(row.task, "relay_publish");
        // Public kinds *are* digested, unlike the encrypted ones: the payload
        // is world-readable anyway, and the digest is what lets a user prove
        // later which manifest they published.
        assert!(
            row.payload_digest.is_some(),
            "a public payload was not digested: {row:?}"
        );
    }

    let policies: Vec<&str> = log.iter().map(|r| r.policy_id.as_str()).collect();
    assert!(
        policies.iter().any(|p| p.contains("revocation")),
        "the revocation's exemption is not recorded: {policies:?}"
    );
}
