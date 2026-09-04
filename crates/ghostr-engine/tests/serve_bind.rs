//! The startup banner must not describe a server that does not exist.
//!
//! # This binds a socket, and that is not a network call
//!
//! CLAUDE.md §4.8 bans network calls in tests, and means reaching a service.
//! This holds a loopback port against itself to make a bind fail. Nothing
//! leaves the machine and there is no external dependency.
//!
//! # The bug
//!
//! `ghostr serve` printed the URL, the token and the QR code and *then* bound
//! the listener. With the port already taken the user got a full "open this
//! link" screen followed by an error — and if the process holding the port was
//! another vault's `ghostr serve`, the link went to that vault instead, with a
//! token that does not work there. It cost twenty screenshots before it was
//! noticed: a preview run pointed a browser at the URL a dead server had
//! printed, reached the live server from an earlier run, and recorded twenty
//! copies of the 401 screen as if they were the product.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::TcpListener;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};

use chrono_tz::Tz;
use ghostr_crypto::kdf::Argon2Params;
use ghostr_crypto::secret::SecretString;
use ghostr_engine::engine::Engine;
use ghostr_engine::serve::{Bind, Token};

fn passphrase() -> SecretString {
    SecretString::new("correct horse battery staple".to_owned())
}

fn vault(dir: &Path) -> Engine {
    Engine::init(
        dir,
        &passphrase(),
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
    Engine::open(dir, &passphrase()).expect("open")
}

/// A bind that fails announces nothing.
#[test]
fn a_taken_port_is_never_announced_as_ready() {
    let home = tempfile::tempdir().unwrap();
    let engine = vault(&home.path().join("vault"));
    let token = Token::mint(&engine);

    // Held for the length of the test, so the bind below cannot succeed.
    let squatter = TcpListener::bind("127.0.0.1:0").expect("hold a port");
    let addr = squatter.local_addr().expect("addr");

    let announced = AtomicBool::new(false);
    let bind = Bind {
        http: Some(addr),
        lan_acknowledged: false,
    };
    let result = ghostr_engine::serve::serve(engine, &bind, &token, || {
        announced.store(true, Ordering::SeqCst);
    });

    let error = result.expect_err("binding a held port must fail");
    assert!(
        error.to_string().contains(&addr.to_string()),
        "the error must name the address that could not be bound: {error}"
    );
    assert!(
        !announced.load(Ordering::SeqCst),
        "a server that never bound told the user it was listening"
    );
}
