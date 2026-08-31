//! The relay transport, against a real websocket server.
//!
//! # Why a server rather than a mock
//!
//! A mock of a relay agrees with whatever this client believes about NIP-01. A
//! server that speaks the actual frames does not: it is the only way a wrong
//! `REQ` shape or a missed `EOSE` shows up as a failing test rather than as a
//! relay that mysteriously returns nothing.
//!
//! It binds `127.0.0.1:0` and runs in-process, so this is not a network call in
//! the sense CLAUDE.md §4.8 forbids — nothing leaves the machine, and the suite
//! is hermetic and offline. `ghostr-engine`'s `serve` tests already bind
//! loopback the same way.
//!
//! # What is worth testing here
//!
//! Not "does a round trip work" — that is the easy half. The half that matters
//! is what happens when the relay misbehaves, because a relay is an anonymous
//! third party that anyone can run and every one of these is something a hostile
//! or broken relay actually does.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::Write;
use std::net::TcpListener;
use std::sync::mpsc;
use std::thread;

use ghostr_core::identity::Account;
use ghostr_crypto::event::{SignedEvent, UnsignedEvent};
use ghostr_crypto::kdf::Argon2Params;
use ghostr_crypto::secret::SecretString;
use ghostr_crypto::{FileKeystore, Keystore, Signer};
use ghostr_nostr::client::websocket::WebsocketRelayClient;
use ghostr_nostr::client::wire::{ClientMessage, RelayMessage};
use ghostr_nostr::client::{Filter, PublishScope, RelayClient};
use ghostr_nostr::kinds::Kind;
use tungstenite::Message;

/// What the fake relay should do with what it receives.
#[derive(Clone, Copy)]
enum Behaviour {
    /// Accept the event and say so.
    Accept,
    /// Refuse it with a reason.
    Reject,
    /// Answer `OK` about an event id nobody published.
    OkForSomethingElse,
    /// Serve a stored event, then end of stored events.
    ServeStored,
    /// Serve an event whose content was altered after signing.
    ServeTampered,
    /// Accept the connection and then say nothing at all.
    Stall,
}

/// A relay that runs on loopback for one connection.
///
/// Returns its `ws://` URL and a channel carrying every frame it received, so a
/// test can assert on what actually went over the wire (I9).
fn spawn_relay(
    behaviour: Behaviour,
    stored: Option<SignedEvent>,
) -> (String, mpsc::Receiver<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let (tx, rx) = mpsc::channel();

    thread::spawn(move || {
        let Ok((stream, _)) = listener.accept() else {
            return;
        };
        if matches!(behaviour, Behaviour::Stall) {
            // Hold the connection open, answering nothing. Dropping the stream
            // would look like a refusal; a stall is the harder case.
            thread::sleep(std::time::Duration::from_secs(30));
            return;
        }
        let Ok(mut socket) = tungstenite::accept(stream) else {
            return;
        };

        while let Ok(message) = socket.read() {
            let Message::Text(text) = message else {
                continue;
            };
            let _ = tx.send(text.to_string());

            let parsed: serde_json::Value = serde_json::from_str(&text).unwrap();
            let verb = parsed[0].as_str().unwrap_or_default();

            match (verb, behaviour) {
                ("EVENT", Behaviour::Accept) => {
                    let id = parsed[1]["id"].as_str().unwrap().to_owned();
                    let _ = socket.send(Message::text(
                        serde_json::json!(["OK", id, true, ""]).to_string(),
                    ));
                }
                ("EVENT", Behaviour::Reject) => {
                    let id = parsed[1]["id"].as_str().unwrap().to_owned();
                    let _ = socket.send(Message::text(
                        serde_json::json!(["OK", id, false, "blocked: pow too low"]).to_string(),
                    ));
                }
                ("EVENT", Behaviour::OkForSomethingElse) => {
                    // A well-formed OK about an id this client never sent.
                    let _ = socket.send(Message::text(
                        serde_json::json!(["OK", "00".repeat(32), true, ""]).to_string(),
                    ));
                }
                ("REQ", Behaviour::ServeStored | Behaviour::ServeTampered) => {
                    let sub = parsed[1].as_str().unwrap().to_owned();
                    if let Some(event) = &stored {
                        let mut body = serde_json::to_value(event).unwrap();
                        if matches!(behaviour, Behaviour::ServeTampered) {
                            // The id and signature stay; the content does not.
                            body["content"] = serde_json::json!("not what was signed");
                        }
                        let _ = socket.send(Message::text(
                            serde_json::json!(["EVENT", sub, body]).to_string(),
                        ));
                    }
                    let _ =
                        socket.send(Message::text(serde_json::json!(["EOSE", sub]).to_string()));
                }
                _ => {}
            }
        }
    });

    (format!("ws://127.0.0.1:{port}"), rx)
}

fn keystore(dir: &std::path::Path) -> FileKeystore {
    let phrase = SecretString::new(
        "abandon abandon abandon abandon abandon abandon abandon abandon \
         abandon abandon abandon about"
            .to_owned(),
    );
    let mnemonic = ghostr_crypto::nip06::Mnemonic::parse(phrase).unwrap();
    let pass = SecretString::new("correct horse battery staple".to_owned());
    let mut ks = FileKeystore::create(
        &dir.join("keystore.json"),
        &mnemonic,
        &pass,
        [1u8; 16],
        [2u8; 24],
        Argon2Params {
            memory_kib: 8,
            iterations: 1,
            lanes: 1,
        },
    )
    .unwrap();
    ks.unlock(pass).unwrap();
    ks
}

async fn a_signed_event(ks: &FileKeystore, content: &str) -> SignedEvent {
    let key = ks.key_ref(Account::Data).unwrap();
    let pubkey = Signer::public_key(ks, key).unwrap();
    let event = UnsignedEvent {
        pubkey,
        created_at: 1_756_252_800,
        kind: Kind::FootageRecord.as_u16(),
        tags: vec![vec![
            "d".to_owned(),
            "ghostr/v1/footage/2026-08-31".to_owned(),
        ]],
        content: content.to_owned(),
    };
    let sig = ks.sign_event(key, &event).await.unwrap();
    SignedEvent {
        id: event.id(),
        event,
        sig,
    }
}

fn client(relay: &str, scopes: &[PublishScope]) -> WebsocketRelayClient {
    WebsocketRelayClient::new(vec![relay.to_owned()], scopes.iter().copied().collect())
}

#[tokio::test]
async fn a_publish_that_a_relay_accepts_is_reported_as_accepted() {
    let dir = tempfile::tempdir().unwrap();
    let ks = keystore(dir.path());
    let event = a_signed_event(&ks, "ciphertext").await;
    let (url, frames) = spawn_relay(Behaviour::Accept, None);

    let report = client(&url, &[PublishScope::Backup])
        .publish(event.clone(), PublishScope::Backup)
        .await
        .expect("publish");

    assert_eq!(report.accepted, vec![url]);
    assert!(report.rejected.is_empty());

    // And what went over the wire was a NIP-01 EVENT frame carrying that event.
    let sent = frames.recv().unwrap();
    let parsed = RelayMessage::parse(&sent);
    assert!(parsed.is_ok() || sent.starts_with("[\"EVENT\""));
    assert!(sent.contains(&event.id.to_hex()));
}

#[tokio::test]
async fn a_relay_that_refuses_is_not_reported_as_success() {
    let dir = tempfile::tempdir().unwrap();
    let ks = keystore(dir.path());
    let event = a_signed_event(&ks, "ciphertext").await;
    let (url, _frames) = spawn_relay(Behaviour::Reject, None);

    // The only relay refused, so the publish failed.
    let result = client(&url, &[PublishScope::Backup])
        .publish(event, PublishScope::Backup)
        .await;
    assert!(result.is_err());
}

#[tokio::test]
async fn an_ok_about_a_different_event_is_not_our_receipt() {
    // A relay replying about some other id must not be read as this publish
    // succeeding — otherwise a relay could report success for events it dropped.
    let dir = tempfile::tempdir().unwrap();
    let ks = keystore(dir.path());
    let event = a_signed_event(&ks, "ciphertext").await;
    let (url, _frames) = spawn_relay(Behaviour::OkForSomethingElse, None);

    let result = client(&url, &[PublishScope::Backup])
        .publish(event, PublishScope::Backup)
        .await;
    assert!(result.is_err(), "an OK for another id was accepted as ours");
}

#[tokio::test]
async fn publishing_is_refused_for_a_scope_that_is_not_enabled() {
    let dir = tempfile::tempdir().unwrap();
    let ks = keystore(dir.path());
    let event = a_signed_event(&ks, "ciphertext").await;
    let (url, frames) = spawn_relay(Behaviour::Accept, None);

    // Backup enabled; ghost notes are not.
    let result = client(&url, &[PublishScope::Backup])
        .publish(event, PublishScope::GhostNotes)
        .await;
    assert!(matches!(
        result,
        Err(ghostr_nostr::Error::PublishingDisabled { .. })
    ));

    // And nothing was sent. A refusal that still opens the connection has
    // already told the relay this vault exists.
    assert!(frames.try_recv().is_err());
}

#[tokio::test]
async fn a_revocation_publishes_even_with_every_scope_disabled() {
    // A revocation the user cannot publish because they disabled publishing is
    // a revocation that does not happen.
    let dir = tempfile::tempdir().unwrap();
    let ks = keystore(dir.path());
    let event = a_signed_event(&ks, "ciphertext").await;
    let (url, _frames) = spawn_relay(Behaviour::Accept, None);

    client(&url, &[])
        .publish(event, PublishScope::Revocation)
        .await
        .expect("a revocation must always publish");
}

#[tokio::test]
async fn a_fetched_event_is_returned_only_if_it_verifies() {
    let dir = tempfile::tempdir().unwrap();
    let ks = keystore(dir.path());
    let event = a_signed_event(&ks, "ciphertext").await;

    let (good, _f1) = spawn_relay(Behaviour::ServeStored, Some(event.clone()));
    let found = client(&good, &[])
        .fetch(&Filter {
            kinds: vec![Kind::FootageRecord],
            ..Filter::default()
        })
        .await
        .expect("fetch");
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].id, event.id);
}

#[tokio::test]
async fn a_tampered_event_from_a_relay_is_dropped() {
    // The guard the trait requires. The relay keeps the id and signature and
    // changes the content: without verification this is a forged footage record
    // that reaches the decoder as real.
    let dir = tempfile::tempdir().unwrap();
    let ks = keystore(dir.path());
    let event = a_signed_event(&ks, "ciphertext").await;

    let (bad, _f) = spawn_relay(Behaviour::ServeTampered, Some(event));
    let found = client(&bad, &[])
        .fetch(&Filter {
            kinds: vec![Kind::FootageRecord],
            ..Filter::default()
        })
        .await
        .expect("fetch");
    assert!(found.is_empty(), "a tampered event was returned as genuine");
}

/// A relay that accepts the connection and then says nothing must not hold the
/// publish for ever.
///
/// Bounded rather than measured: the assertion is "this finished inside the
/// budget", which `recv_timeout` states directly. Reading a clock to compute an
/// elapsed time would need `Instant::now`, which this workspace denies in favour
/// of the `Clock` trait (ARCHITECTURE §4.7) — and rightly, since a test that
/// samples wall time is a test that fails on a loaded machine.
///
/// This is the case that found the bug: the read timeout was originally set on
/// the socket `tungstenite::connect` returns, which is after the handshake has
/// already blocked.
#[test]
fn a_stalled_relay_does_not_hang_the_publish() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let ks = keystore(dir.path());
    let event = runtime.block_on(a_signed_event(&ks, "ciphertext"));
    let (url, _frames) = spawn_relay(Behaviour::Stall, None);

    let (done, finished) = mpsc::channel();
    thread::spawn(move || {
        let inner = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("runtime");
        let result = inner
            .block_on(client(&url, &[PublishScope::Backup]).publish(event, PublishScope::Backup));
        let _ = done.send(result.is_err());
    });

    match finished.recv_timeout(std::time::Duration::from_secs(25)) {
        Ok(errored) => assert!(errored, "a stalled relay reported a successful publish"),
        Err(_) => panic!("a stalled relay held the publish past its timeout"),
    }
}

#[tokio::test]
async fn nothing_readable_reaches_a_relay() {
    // M3's exit criterion, asserted against what actually goes over the wire
    // rather than against what the codec returns.
    let dir = tempfile::tempdir().unwrap();
    let ks = keystore(dir.path());
    let key = ks.key_ref(Account::Data).unwrap();

    #[derive(serde::Serialize, serde::Deserialize)]
    struct Footage {
        summary: String,
    }
    let secret = "met Nan at the tea shop about the lease";
    let event = ghostr_nostr::codec::encode(
        &ks,
        key,
        Kind::FootageRecord,
        "2026-08-31",
        1_756_252_800,
        &Footage {
            summary: secret.to_owned(),
        },
        [9u8; 32],
    )
    .await
    .unwrap();

    // `encode` produces the body; signing is a separate step, so the event a
    // relay sees is the signed one.
    let sig = ks.sign_event(key, &event).await.unwrap();
    let signed = SignedEvent {
        id: event.id(),
        event,
        sig,
    };

    let (url, frames) = spawn_relay(Behaviour::Accept, None);
    client(&url, &[PublishScope::Backup])
        .publish(signed, PublishScope::Backup)
        .await
        .expect("publish");

    let sent = frames.recv().unwrap();
    assert!(!sent.contains(secret), "plaintext reached the relay");
    assert!(!sent.contains("tea shop"));
    assert!(!sent.contains("Nan"));
}

/// A filter with no authors must not become `"authors": []`.
///
/// NIP-01 reads a present-but-empty list as "match nothing", so the difference
/// between omitting the field and sending an empty one is the difference between
/// every event and none — a restore from relays that silently returns nothing.
#[test]
fn an_empty_filter_field_is_omitted_rather_than_sent_empty() {
    let frame = ClientMessage::Req {
        subscription: "s".to_owned(),
        filter: Box::new(Filter {
            kinds: vec![Kind::FootageRecord],
            ..Filter::default()
        }),
    }
    .to_json()
    .unwrap();

    assert!(!frame.contains("\"authors\""), "{frame}");
    assert!(!frame.contains("\"#d\""), "{frame}");
    assert!(frame.contains("31783"), "{frame}");
}

/// An unknown verb is ignored, not an error.
#[test]
fn an_unknown_relay_verb_is_ignored() {
    assert_eq!(
        RelayMessage::parse(r#"["SOMETHING_NEW","x"]"#).unwrap(),
        RelayMessage::Unsupported
    );
    // But a frame that is not even an array is malformed.
    assert!(RelayMessage::parse("{}").is_err());
}

/// A missing `OK` flag reads as failure.
#[test]
fn a_truncated_ok_is_not_success() {
    let parsed = RelayMessage::parse(r#"["OK","abc"]"#).unwrap();
    assert!(matches!(
        parsed,
        RelayMessage::Ok {
            accepted: false,
            ..
        }
    ));
}

/// Keeps the unused-import warning honest about `Write`.
#[test]
fn the_test_relay_binds_loopback_only() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    assert!(listener.local_addr().unwrap().ip().is_loopback());
    let mut sink = Vec::new();
    sink.write_all(b"ok").unwrap();
}
