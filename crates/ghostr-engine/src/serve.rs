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

/// Runs the server until interrupted.
///
/// Connections are served one at a time, and deliberately: [`Engine`] owns a
/// `SqliteStore` that is not `Sync`, so there is no shared-state race to get
/// wrong because there is no sharing. One person answering quests on their
/// phone does not need concurrency, and a threadpool here would buy nothing but
/// a class of bug.
///
/// # Errors
///
/// Returns [`Error::Config`](crate::Error::Config) if a listener cannot be
/// bound.
pub fn serve(engine: &Engine, bind: &Bind, token: &Token) -> crate::Result<()> {
    let mut listeners = Listeners::bind(engine, bind)?;
    loop {
        match listeners.accept() {
            Ok(mut stream) => {
                let response = handle_connection(engine, token, stream.as_mut());
                // A write that fails is a client that hung up. Not an error
                // worth stopping the server for, and not one worth logging
                // either — a phone locking its screen does this constantly.
                let _ = stream.as_mut().write_all(&response);
                let _ = stream.as_mut().flush();
            }
            // Same reasoning: a failed accept is one client's problem.
            Err(_) => continue,
        }
    }
}

/// Reads one request and produces its response.
fn handle_connection(engine: &Engine, token: &Token, stream: &mut dyn Stream) -> Vec<u8> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 8 * 1024];

    loop {
        match http::parse(&buf) {
            Ok(Ok(request)) => return api::route(engine, token, &request, UI_HTML),
            Err(status) => return http::error_response(status),
            Ok(Err(needed)) => {
                if let http::Incomplete::NeedBody { total } = needed
                    && total > MAX_REQUEST
                {
                    return http::error_response(http::Status::PayloadTooLarge);
                }
                if buf.len() >= MAX_REQUEST {
                    return http::error_response(http::Status::PayloadTooLarge);
                }
            }
        }

        match stream.read(&mut chunk) {
            // The client stopped sending mid-request.
            Ok(0) => return http::error_response(http::Status::BadRequest),
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(_) => return http::error_response(http::Status::BadRequest),
        }
    }
}

/// The two stream kinds, behind one interface.
trait Stream: std::io::Read + std::io::Write {}
impl<T: std::io::Read + std::io::Write> Stream for T {}

/// An accepted connection from either listener.
enum Accepted {
    Tcp(std::net::TcpStream),
    #[cfg(unix)]
    Unix(std::os::unix::net::UnixStream),
}

impl Accepted {
    fn as_mut(&mut self) -> &mut dyn Stream {
        match self {
            Self::Tcp(s) => s,
            #[cfg(unix)]
            Self::Unix(s) => s,
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

    /// Waits for the next connection on either listener.
    ///
    /// Polls rather than selects. `std` has no `select`, and pulling in an
    /// event loop for two listeners serving one person would be the tail
    /// wagging the dog. The sleep is what keeps an idle server off the CPU.
    fn accept(&mut self) -> std::io::Result<Accepted> {
        loop {
            #[cfg(unix)]
            if let Some(listener) = &self.unix {
                listener.set_nonblocking(true)?;
                match listener.accept() {
                    Ok((stream, _)) => {
                        stream.set_nonblocking(false)?;
                        stream.set_read_timeout(Some(IO_TIMEOUT))?;
                        stream.set_write_timeout(Some(IO_TIMEOUT))?;
                        return Ok(Accepted::Unix(stream));
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                    Err(e) => return Err(e),
                }
            }

            if let Some(listener) = &self.tcp {
                listener.set_nonblocking(true)?;
                match listener.accept() {
                    Ok((stream, _)) => {
                        stream.set_nonblocking(false)?;
                        stream.set_read_timeout(Some(IO_TIMEOUT))?;
                        stream.set_write_timeout(Some(IO_TIMEOUT))?;
                        return Ok(Accepted::Tcp(stream));
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                    Err(e) => return Err(e),
                }
            }

            std::thread::sleep(Duration::from_millis(25));
        }
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
