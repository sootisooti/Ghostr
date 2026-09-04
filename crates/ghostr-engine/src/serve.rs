//! The local API, and the page it serves.
//!
//! # Two listeners, one of them off by default
//!
//! The documented local API is a Unix domain socket (ARCHITECTURE §5): no port,
//! no network stack, and filesystem permissions doing the access control. That
//! is what `ghostr serve` binds, always.
//!
//! A phone cannot reach a Unix socket, so `--http` opts into a TCP listener as
//! well. It binds loopback unless told otherwise, and binding anything else
//! needs `--lan` on top — a second flag whose only job is to make the user say
//! out loud that they are putting their journal on a network.
//!
//! # What the token is for
//!
//! On loopback the token stops *other local processes* — every browser tab, every
//! script — from reading the vault by guessing a port. On a LAN it is the only
//! thing standing between the corpus and anyone else on the wifi. It is
//! compared in constant time, it is never logged, and it never appears in a URL
//! path or query: the page receives it in the fragment, which browsers do not
//! send to servers and proxies do not log.

pub mod api;
pub mod http;
pub mod icon;

use std::time::Duration;

use crate::engine::Engine;

/// The page, compiled in.
///
/// One self-contained file: no CDN, no external stylesheet, no font fetch. A
/// page that reached out for an asset would announce the vault's existence to
/// whoever served it, on every load.
const UI_HTML: &str = include_str!("serve/ui.html");

/// How long a client may take to send its request.
///
/// Connections are handled one at a time, so a client that opens a socket and
/// says nothing would otherwise stall the whole server. Short, because every
/// legitimate client here is on the same machine or the same room's wifi.
const IO_TIMEOUT: Duration = Duration::from_secs(10);

/// The largest request this server will read, headers and body together.
const MAX_REQUEST: usize = 96 * 1024;

/// The default TCP port, when `--http` is given without one.
///
/// Unregistered, and not one anything else is likely to be sitting on.
pub const DEFAULT_PORT: u16 = 7749;

/// The socket file inside the vault directory.
pub const SOCKET_FILENAME: &str = "ghostr.sock";

/// A bearer token for the local API.
///
/// Holds the bytes rather than a `String` so the comparison can be constant
/// time and so `Debug` cannot print it.
pub struct Token(String);

impl core::fmt::Debug for Token {
    /// Never the value. A token in a log is a token in a bug report (I8).
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Token(<redacted>)")
    }
}

impl Token {
    /// Mints a token from the engine's entropy.
    #[must_use]
    pub fn mint(engine: &Engine) -> Self {
        let mut raw = [0u8; 32];
        engine.rng().fill(&mut raw);
        Self(hex::encode(raw))
    }

    /// The token, for printing once at startup.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// Whether a presented token matches.
    ///
    /// Constant time in the length of the stored token. A byte-at-a-time
    /// comparison that returns early leaks the token one byte per request, and
    /// a local attacker can make a great many requests.
    #[must_use]
    pub fn matches(&self, presented: &str) -> bool {
        let expected = self.0.as_bytes();
        let got = presented.as_bytes();
        // Length is not secret — it is a fixed 64 hex characters — so comparing
        // it up front reveals nothing that reading this file would not.
        if expected.len() != got.len() {
            return false;
        }
        let mut difference = 0u8;
        for (a, b) in expected.iter().zip(got.iter()) {
            difference |= a ^ b;
        }
        difference == 0
    }
}

/// Where the server listens.
#[derive(Debug, Clone)]
pub struct Bind {
    /// The TCP address, if `--http` was given.
    pub http: Option<std::net::SocketAddr>,
    /// Whether the user acknowledged a non-loopback bind.
    pub lan_acknowledged: bool,
}

/// Whether an address is reachable only from this machine.
#[must_use]
pub fn is_loopback(addr: &std::net::SocketAddr) -> bool {
    addr.ip().is_loopback()
}

/// The most connections served at once.
///
/// Safari opens several speculative connections per host and leaves some of
/// them silent, so a server that handled one at a time would spend its life in
/// a read timeout while the page appeared frozen. Bounded because unbounded
/// threads is a denial of service anyone on the network could trigger.
const MAX_CONNECTIONS: usize = 32;

/// Runs the server until interrupted.
///
/// # Why threads, given the engine is not `Sync`
///
/// It handles connections concurrently but touches the vault under a mutex, and
/// the split is the whole point: **a request is read and parsed before the lock
/// is taken.** A client that connects and says nothing therefore holds a thread
/// and nothing else, where a sequential server would have made every other
/// request wait out its read timeout. Measured on loopback, one silent
/// connection took the next page load from 31ms to 9.3 seconds; a phone does
/// this constantly.
///
/// Work against the store still serialises, which is correct rather than
/// merely convenient — `SqliteStore` holds a connection that is `Send` but not
/// `Sync`, so there is one writer by construction and no interleaving to get
/// wrong.
///
/// # Errors
///
/// Returns [`Error::Config`](crate::Error::Config) if a listener cannot be
/// bound.
pub fn serve(engine: Engine, bind: &Bind, token: &Token) -> crate::Result<()> {
    use std::io::Write as _;

    let listeners = Listeners::bind(&engine, bind)?;
    let engine = std::sync::Mutex::new(engine);
    let live = std::sync::atomic::AtomicUsize::new(0);

    std::thread::scope(|scope| {
        let mut acceptors = Vec::new();

        // The sealer. `serve` is where this belongs because it is the one
        // process that already holds an unlocked vault — the alternative is a
        // cron job, and a cron job needs the passphrase in an environment
        // variable or a file, which is a worse trade than running a server.
        let sealer = scope.spawn({
            let engine = &engine;
            move || seal_loop(engine)
        });
        acceptors.push(sealer);
        for listener in listeners.into_streams() {
            let engine = &engine;
            let live = &live;
            acceptors.push(scope.spawn(move || {
                for stream in listener {
                    let Ok(mut stream) = stream else {
                        // One client's failure to connect is not the server's
                        // problem, and not worth a log line either.
                        continue;
                    };
                    let _ = stream.set_timeouts(IO_TIMEOUT);

                    if live.fetch_add(1, std::sync::atomic::Ordering::AcqRel) >= MAX_CONNECTIONS {
                        live.fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
                        // Refused immediately rather than queued. A queue here
                        // is just a slower way to be unavailable.
                        let _ = stream.write_all(&http::error_response(http::Status::Unavailable));
                        continue;
                    }

                    scope.spawn(move || {
                        let response = handle(engine, token, &mut stream);
                        // A write that fails is a client that hung up — a phone
                        // locking its screen does this constantly.
                        let _ = stream.write_all(&response);
                        let _ = stream.flush();
                        live.fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
                    });
                }
            }));
        }
        for acceptor in acceptors {
            let _ = acceptor.join();
        }
    });

    Ok(())
}

/// How often the sealer looks for a day that is over.
///
/// Fifteen minutes. The thing it is waiting for moves once a day, so this is
/// about how promptly a machine that was asleep at the cutoff catches up rather
/// than about precision.
const SEAL_CHECK_INTERVAL: Duration = Duration::from_secs(15 * 60);

/// Seals days that are over, for as long as the server runs.
///
/// Failures are swallowed deliberately. This runs beside a web server, and a
/// day that cannot be sealed — a replica, a locked vault, a model that will not
/// answer — must not take the page down with it. The next pass tries again, and
/// `ghostr status` is where a user finds out the chain is behind.
fn seal_loop(engine: &std::sync::Mutex<Engine>) {
    loop {
        std::thread::sleep(SEAL_CHECK_INTERVAL);

        let guard = engine
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        // Read every pass rather than once at startup: a user who turns this on
        // should not have to restart the server to get it.
        let Ok(config) = guard.config() else {
            continue;
        };
        if !config.auto_seal {
            continue;
        }
        let _ = crate::ops::seal_due(&guard, config.seal_grace_hours, config.seal_backfill_days);
    }
}

/// Reads one request, then answers it.
///
/// The read happens outside the lock and the routing inside it. That ordering
/// is what keeps a slow client from stalling a fast one.
fn handle(engine: &std::sync::Mutex<Engine>, token: &Token, stream: &mut Accepted) -> Vec<u8> {
    let buf = match read_request(stream) {
        Ok(buf) => buf,
        Err(status) => return http::error_response(status),
    };
    let request = match http::parse(&buf) {
        Ok(Ok(request)) => request,
        Ok(Err(_)) => return http::error_response(http::Status::BadRequest),
        Err(status) => return http::error_response(status),
    };

    // Poisoned means another request panicked mid-handler. The vault itself is
    // fine — every write is a transaction — so recovering and serving the next
    // request beats refusing every request from now on.
    let engine = engine
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    api::route(&engine, token, &request, UI_HTML)
}

/// Reads until a complete request has arrived, or refuses.
fn read_request<R: std::io::Read>(stream: &mut R) -> Result<Vec<u8>, http::Status> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 8 * 1024];

    loop {
        match http::parse(&buf) {
            Ok(Ok(_)) => return Ok(buf),
            Err(status) => return Err(status),
            Ok(Err(needed)) => {
                if let http::Incomplete::NeedBody { total } = needed
                    && total > MAX_REQUEST
                {
                    return Err(http::Status::PayloadTooLarge);
                }
                if buf.len() >= MAX_REQUEST {
                    return Err(http::Status::PayloadTooLarge);
                }
            }
        }

        match stream.read(&mut chunk) {
            // The client stopped sending mid-request, or never started.
            Ok(0) => return Err(http::Status::BadRequest),
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(_) => return Err(http::Status::BadRequest),
        }
    }
}

/// An accepted connection from either listener.
enum Accepted {
    Tcp(std::net::TcpStream),
    #[cfg(unix)]
    Unix(std::os::unix::net::UnixStream),
}

impl Accepted {
    /// Bounds how long a client may take, in both directions.
    fn set_timeouts(&self, timeout: Duration) -> std::io::Result<()> {
        match self {
            Self::Tcp(s) => {
                s.set_read_timeout(Some(timeout))?;
                s.set_write_timeout(Some(timeout))
            }
            #[cfg(unix)]
            Self::Unix(s) => {
                s.set_read_timeout(Some(timeout))?;
                s.set_write_timeout(Some(timeout))
            }
        }
    }
}

impl std::io::Read for Accepted {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::Tcp(s) => s.read(buf),
            #[cfg(unix)]
            Self::Unix(s) => s.read(buf),
        }
    }
}

impl std::io::Write for Accepted {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            Self::Tcp(s) => s.write(buf),
            #[cfg(unix)]
            Self::Unix(s) => s.write(buf),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Self::Tcp(s) => s.flush(),
            #[cfg(unix)]
            Self::Unix(s) => s.flush(),
        }
    }
}

/// A listener, as an endless iterator of connections.
///
/// One per listener so each can block on its own `accept`. `std` has no
/// `select`, and the alternative — polling both with a sleep between — adds
/// latency to every request to save a thread.
enum Incoming {
    Tcp(std::net::TcpListener),
    #[cfg(unix)]
    Unix(std::os::unix::net::UnixListener),
}

impl IntoIterator for Incoming {
    type Item = std::io::Result<Accepted>;
    type IntoIter = Box<dyn Iterator<Item = Self::Item> + Send>;

    fn into_iter(self) -> Self::IntoIter {
        match self {
            Self::Tcp(l) => Box::new(std::iter::from_fn(move || {
                Some(l.accept().map(|(s, _)| Accepted::Tcp(s)))
            })),
            #[cfg(unix)]
            Self::Unix(l) => Box::new(std::iter::from_fn(move || {
                Some(l.accept().map(|(s, _)| Accepted::Unix(s)))
            })),
        }
    }
}

/// The bound listeners.
struct Listeners {
    tcp: Option<std::net::TcpListener>,
    #[cfg(unix)]
    unix: Option<std::os::unix::net::UnixListener>,
}

impl Listeners {
    fn bind(engine: &Engine, bind: &Bind) -> crate::Result<Self> {
        #[cfg(unix)]
        let unix = {
            let path = engine.dir().join(SOCKET_FILENAME);
            // A socket left behind by a killed process would make every
            // subsequent start fail. Removing it is safe: the path is inside
            // the vault directory and named by this crate.
            let _ = std::fs::remove_file(&path);
            let listener = std::os::unix::net::UnixListener::bind(&path).map_err(|e| {
                crate::Error::Config {
                    detail: format!("cannot bind {}: {e}", path.display()),
                }
            })?;
            restrict_socket(&path)?;
            Some(listener)
        };

        let tcp = match bind.http {
            Some(addr) => {
                Some(
                    std::net::TcpListener::bind(addr).map_err(|e| crate::Error::Config {
                        detail: format!("cannot bind {addr}: {e}"),
                    })?,
                )
            }
            None => None,
        };

        Ok(Self {
            tcp,
            #[cfg(unix)]
            unix,
        })
    }

    /// The listeners, each ready to be blocked on by its own thread.
    fn into_streams(self) -> Vec<Incoming> {
        let mut out = Vec::new();
        #[cfg(unix)]
        if let Some(listener) = self.unix {
            out.push(Incoming::Unix(listener));
        }
        if let Some(listener) = self.tcp {
            out.push(Incoming::Tcp(listener));
        }
        out
    }
}

/// Makes the socket readable only by its owner.
///
/// Without this, the socket's permissions come from the process umask, and a
/// permissive umask would hand every local account a door into the vault that
/// needs no token at all.
#[cfg(unix)]
fn restrict_socket(path: &std::path::Path) -> crate::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;

    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).map_err(|e| {
        crate::Error::Config {
            detail: format!("cannot restrict {}: {e}", path.display()),
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A token that returned early on the first differing byte would leak
    /// itself one byte per request, and a local attacker can make a great many
    /// requests.
    #[test]
    fn a_token_matches_only_itself() {
        let token = Token("a".repeat(64));
        assert!(token.matches(&"a".repeat(64)));
        assert!(!token.matches(&"b".repeat(64)));
        // A prefix must not pass, which is the whole point of comparing lengths
        // before bytes.
        assert!(!token.matches("a"));
        assert!(!token.matches(&"a".repeat(65)));
        assert!(!token.matches(""));
    }

    /// I8. A token in a log line is a token in a bug report.
    #[test]
    fn a_token_never_debug_prints_itself() {
        let token = Token("s3cret".repeat(8));
        let rendered = format!("{token:?}");
        assert!(!rendered.contains("s3cret"));
        assert_eq!(rendered, "Token(<redacted>)");
    }

    /// A request arriving in dribs and drabs is still one request. A phone on
    /// a weak signal produces exactly this.
    #[test]
    fn a_request_split_across_reads_is_assembled() {
        struct Trickle(Vec<Vec<u8>>);
        impl std::io::Read for Trickle {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                if self.0.is_empty() {
                    return Ok(0);
                }
                let chunk = self.0.remove(0);
                buf[..chunk.len()].copy_from_slice(&chunk);
                Ok(chunk.len())
            }
        }

        let mut stream = Trickle(vec![
            b"POST /api/x HTTP/1.1\r\n".to_vec(),
            b"Content-Length: 5\r\n\r\n".to_vec(),
            b"hel".to_vec(),
            b"lo".to_vec(),
        ]);
        let buf = read_request(&mut stream).expect("assembled");
        let request = http::parse(&buf).expect("accepted").expect("complete");
        assert_eq!(request.body, b"hello");
    }

    /// A client that connects and says nothing gets a refusal, not a buffer.
    #[test]
    fn a_silent_client_is_refused_rather_than_waited_on_forever() {
        let mut nothing = std::io::empty();
        assert_eq!(
            read_request(&mut nothing),
            Err(http::Status::BadRequest),
            "a connection that sends nothing is not a request"
        );
    }

    #[test]
    fn loopback_is_told_apart_from_everything_else() {
        let loopback: std::net::SocketAddr = "127.0.0.1:7749".parse().expect("addr");
        let v6: std::net::SocketAddr = "[::1]:7749".parse().expect("addr");
        let lan: std::net::SocketAddr = "192.168.1.20:7749".parse().expect("addr");
        let any: std::net::SocketAddr = "0.0.0.0:7749".parse().expect("addr");

        assert!(is_loopback(&loopback));
        assert!(is_loopback(&v6));
        assert!(!is_loopback(&lan));
        assert!(!is_loopback(&any), "0.0.0.0 reaches every interface");
    }
}
