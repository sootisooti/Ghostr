//! `bunker://` parsing — the whole user-facing surface of remote signing.
//!
//! The user pastes a string their signer gave them, and what comes out decides
//! who this vault treats as its signer and which relays it talks to. So the
//! cases worth testing are the malformed ones: a parser that repairs a mistyped
//! URL is choosing those on the user's behalf.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use ghostr_nostr::nip46::bunker::BunkerUrl;

/// A real curve point, from NIP-19's published vector.
const SIGNER: &str = "7e7e9c42a91bfef19fa929e5fda1b72e0ebc1a4c1141673e2794234d86addf4e";

#[test]
fn the_nip46_example_shape_parses() {
    let url = format!("bunker://{SIGNER}?relay=wss%3A%2F%2Frelay.example.com&secret=0s8j2djs");
    let parsed = BunkerUrl::parse(&url).expect("parse");

    assert_eq!(parsed.signer_pubkey.to_hex(), SIGNER);
    // Percent-escapes decoded: a relay URL survives the query encoding.
    assert_eq!(parsed.relays, vec!["wss://relay.example.com"]);
    assert!(parsed.secret.is_some());
}

#[test]
fn several_relays_are_all_kept() {
    let url =
        format!("bunker://{SIGNER}?relay=wss%3A%2F%2Fone.example&relay=wss%3A%2F%2Ftwo.example");
    let parsed = BunkerUrl::parse(&url).expect("parse");
    assert_eq!(
        parsed.relays,
        vec!["wss://one.example", "wss://two.example"]
    );
    assert!(parsed.secret.is_none());
}

/// An unknown parameter does not fail the URL.
///
/// NIP-46 gains parameters over time, and a client that refuses a URL for
/// carrying one it has not heard of breaks on the signer's next release.
#[test]
fn an_unknown_parameter_is_ignored() {
    let url = format!("bunker://{SIGNER}?relay=wss%3A%2F%2Fone.example&perms=sign_event%3A1");
    assert!(BunkerUrl::parse(&url).is_ok());
}

#[test]
fn a_url_with_no_relay_is_refused() {
    // NIP-46 has no transport other than relays, so a signer with none named
    // cannot be reached — better to say so at paste time.
    assert!(BunkerUrl::parse(&format!("bunker://{SIGNER}")).is_err());
    assert!(BunkerUrl::parse(&format!("bunker://{SIGNER}?secret=abc")).is_err());
}

#[test]
fn a_non_websocket_relay_is_refused() {
    let url = format!("bunker://{SIGNER}?relay=https%3A%2F%2Frelay.example.com");
    assert!(BunkerUrl::parse(&url).is_err());
}

/// A pubkey that is not a curve point fails at paste time.
///
/// It cannot receive an encrypted request, so the alternative is a silent
/// failure much later, when the user has forgotten what they pasted.
#[test]
fn a_pubkey_that_is_not_on_the_curve_is_refused() {
    // Right length, right alphabet, not a point.
    let url = "bunker://ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\
               ?relay=wss%3A%2F%2Fone.example";
    assert!(BunkerUrl::parse(url).is_err());
}

#[test]
fn a_malformed_pubkey_is_refused() {
    for bad in [
        // Too short.
        "bunker://7e7e9c42?relay=wss%3A%2F%2Fone.example",
        // Not hex.
        "bunker://zzzz9c42a91bfef19fa929e5fda1b72e0ebc1a4c1141673e2794234d86addf4e\
         ?relay=wss%3A%2F%2Fone.example",
        // An npub rather than hex.
        "bunker://npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkwsyjh6w6\
         ?relay=wss%3A%2F%2Fone.example",
    ] {
        assert!(BunkerUrl::parse(bad).is_err(), "{bad} should be refused");
    }
}

#[test]
fn another_scheme_is_not_a_bunker_url() {
    for bad in [
        // `nostrconnect://` is the *other* NIP-46 flow and is not this one.
        "nostrconnect://7e7e9c42a91bfef19fa929e5fda1b72e0ebc1a4c1141673e2794234d86addf4e\
         ?relay=wss%3A%2F%2Fone.example",
        "https://example.com",
        "",
    ] {
        assert!(BunkerUrl::parse(bad).is_err());
    }
}

/// The secret never reaches a log, even through `Debug`.
#[test]
fn debug_does_not_print_the_connection_secret() {
    let url = format!("bunker://{SIGNER}?relay=wss%3A%2F%2Fone.example&secret=hunter2");
    let parsed = BunkerUrl::parse(&url).expect("parse");
    let printed = format!("{parsed:?}");
    assert!(!printed.contains("hunter2"), "{printed}");
    // And the full signer pubkey is not printed either: a pubkey in a log is a
    // correlation handle for whoever reads the log.
    assert!(!printed.contains(SIGNER), "{printed}");
}
