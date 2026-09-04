//! One slow client must not stall the next.
//!
//! # This binds a socket, and that is not a network call
//!
//! CLAUDE.md §4.8 bans network calls in tests, and means reaching a service:
//! a relay, a calendar, a model provider. This binds a loopback listener on an
//! OS-assigned port and talks to itself. Nothing leaves the machine, there is
//! no external dependency, and the test is as deterministic as any other.
//!
//! It earns the socket because the bug it guards is invisible without one. A
//! sequential server passes every unit test in the suite and still freezes a
//! phone for ten seconds at a time, because Safari opens speculative
//! connections and leaves some of them silent. Measured before the fix: one
//! silent connection took the next page load from 31ms to 9.3 seconds.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
// `clippy.toml` bans wall-clock reads so domain code stays deterministic under
// the `Clock` trait. This test is not domain code: what it measures *is* elapsed
// wall-clock time, and a `Clock` that only moves when told cannot observe a
// thread being blocked. Stated here rather than waived globally, so every
// exception in the workspace stays greppable (ARCHITECTURE §4.7).
#![allow(clippy::disallowed_methods)]

use std::io::{Read as _, Write as _};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::time::{Duration, Instant};

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

/// Asks the OS for a free port, so two runs of this suite never collide.
fn free_port() -> u16 {
    let probe = TcpListener::bind("127.0.0.1:0").expect("probe");
    let port = probe.local_addr().expect("addr").port();
    drop(probe);
    port
}

fn get_page(port: u16) -> std::io::Result<String> {
    let mut stream = TcpStream::connect(("127.0.0.1", port))?;
    stream.set_read_timeout(Some(Duration::from_secs(20)))?;
    stream.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")?;
    let mut out = String::new();
    stream.read_to_string(&mut out)?;
    Ok(out)
}

/// The regression. Six silent connections is roughly what a browser opens per
/// host, and the seventh request is the one the user is waiting on.
#[test]
fn a_silent_connection_does_not_stall_the_next_request() {
    let home = tempfile::tempdir().unwrap();
    let dir = home.path().join("vault");
    let engine = vault(&dir);
    let port = free_port();
    let token = Token::mint(&engine);

    let (up, listening) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let bind = Bind {
            http: Some(std::net::SocketAddr::from(([127, 0, 0, 1], port))),
            lan_acknowledged: false,
        };
        let _ = ghostr_engine::serve::serve(engine, &bind, &token, move || {
            let _ = up.send(());
        });
    });

    // The server says when it is listening, so this waits on the event rather
    // than polling for a connection that succeeds. A poll would also succeed
    // against a *different* process holding the port.
    listening
        .recv_timeout(Duration::from_secs(10))
        .expect("the server never came up");

    let warm = Instant::now();
    assert!(get_page(port).expect("warm-up").contains("200 OK"));
    let baseline = warm.elapsed();

    // Connections that will never send a byte, held for the life of the test.
    let silent: Vec<TcpStream> = (0..6)
        .filter_map(|_| TcpStream::connect(("127.0.0.1", port)).ok())
        .collect();
    assert_eq!(silent.len(), 6, "could not open the silent connections");

    let started = Instant::now();
    let body = get_page(port).expect("served");
    let elapsed = started.elapsed();

    assert!(body.contains("200 OK"), "{body}");
    // The read timeout is ten seconds, so a sequential server lands near that.
    // Two seconds is far below it and far above any honest scheduling delay.
    assert!(
        elapsed < Duration::from_secs(2),
        "a silent connection stalled the next request: {elapsed:?} against a \
         {baseline:?} baseline"
    );

    drop(silent);
}
