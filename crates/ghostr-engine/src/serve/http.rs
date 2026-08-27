//! A minimal HTTP/1.1 server, hand-written.
//!
//! # Why not a framework
//!
//! The surface is one static page and six JSON endpoints, served to one person
//! on their own machine. `axum` would bring `tokio` and `hyper` and roughly
//! double a dependency tree this project keeps deliberately small
//! (THREAT_MODEL §T8). The same reasoning that hand-rolled the passphrase
//! prompt rather than pulling `rpassword` applies here, at a larger scale.
//!
//! # What makes that safe to do
//!
//! Hand-written HTTP is a bad idea when it has to be general. This one is not:
//!
//! - **No keep-alive.** One request per connection, always `Connection: close`.
//!   Request smuggling is a disagreement between two parsers about where one
//!   message ends and the next begins; there is no next message.
//! - **No `Transfer-Encoding`.** Chunked bodies are rejected outright rather
//!   than parsed. That is the other half of smuggling, removed rather than
//!   handled.
//! - **Everything is bounded** before it is read: the request line, the header
//!   block, the header count, and the body each have a hard cap, and exceeding
//!   one is a refusal rather than an allocation.
//! - **Nothing from the request is echoed** into a response. No reflected
//!   header, no reflected path, so there is nothing to inject into.
//! - **Parsing is a pure function** over bytes, so every case above is a unit
//!   test with no socket, no port, and no timing.

/// The most a request line may be. A URL longer than this is not a URL.
const MAX_REQUEST_LINE: usize = 8 * 1024;
/// The most the header block may be, in total.
const MAX_HEADER_BYTES: usize = 16 * 1024;
/// The most headers a request may carry.
const MAX_HEADERS: usize = 64;
/// The most a body may be. Bodies here are short JSON; a correction is a
/// sentence, not a file.
pub const MAX_BODY: usize = 64 * 1024;

/// The methods this server answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    /// A read.
    Get,
    /// A write.
    Post,
}

/// A parsed request, borrowed from the read buffer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request<'a> {
    /// The method.
    pub method: Method,
    /// The path, percent-decoded, without any query string.
    ///
    /// Owned because decoding may change it. Decoding happens *before* the
    /// traversal check, not after: `%2e%2e%2f` is `../` and a check run on the
    /// raw form would not see it.
    pub path: String,
    /// The `Authorization: Bearer` value, if one was sent.
    pub bearer: Option<&'a str>,
    /// The `Origin` header, if one was sent.
    pub origin: Option<&'a str>,
    /// The `Host` header, which is what an `Origin` has to match.
    pub host: Option<&'a str>,
    /// The body.
    pub body: &'a [u8],
}

/// A response status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// 200.
    Ok,
    /// 400.
    BadRequest,
    /// 401.
    Unauthorized,
    /// 403.
    Forbidden,
    /// 404.
    NotFound,
    /// 405.
    MethodNotAllowed,
    /// 409.
    Conflict,
    /// 413.
    PayloadTooLarge,
    /// 422.
    Unprocessable,
    /// 500.
    ServerError,
    /// 503.
    Unavailable,
}

impl Status {
    /// The status line text.
    const fn line(self) -> &'static str {
        match self {
            Self::Ok => "200 OK",
            Self::BadRequest => "400 Bad Request",
            Self::Unauthorized => "401 Unauthorized",
            Self::Forbidden => "403 Forbidden",
            Self::NotFound => "404 Not Found",
            Self::MethodNotAllowed => "405 Method Not Allowed",
            Self::Conflict => "409 Conflict",
            Self::PayloadTooLarge => "413 Payload Too Large",
            Self::Unprocessable => "422 Unprocessable Content",
            Self::ServerError => "500 Internal Server Error",
            Self::Unavailable => "503 Service Unavailable",
        }
    }
}

/// How much of a request has arrived.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Incomplete {
    /// The header block has not finished yet.
    NeedMore,
    /// Headers are in; this many total bytes are needed.
    NeedBody {
        /// Total request length, headers included.
        total: usize,
    },
}

/// Parses a request, or says what is still missing.
///
/// # Errors
///
/// Returns a [`Status`] for a request this server will not accept: malformed,
/// oversized, chunked, or using a method it does not implement.
pub fn parse(buf: &[u8]) -> Result<Result<Request<'_>, Incomplete>, Status> {
    let Some(head_end) = find_head_end(buf) else {
        // Bounded even while incomplete: a client that never sends a blank line
        // must not be able to make us buffer forever.
        if buf.len() > MAX_REQUEST_LINE + MAX_HEADER_BYTES {
            return Err(Status::PayloadTooLarge);
        }
        return Ok(Err(Incomplete::NeedMore));
    };

    let head = &buf[..head_end];
    let body_start = head_end + 4;
    let mut lines = head.split(|b| *b == b'\n');

    let request_line = lines.next().ok_or(Status::BadRequest)?;
    let request_line = strip_cr(request_line);
    if request_line.len() > MAX_REQUEST_LINE {
        return Err(Status::PayloadTooLarge);
    }
    let (method, path) = parse_request_line(request_line)?;

    let mut bearer = None;
    let mut origin = None;
    let mut host = None;
    let mut content_length = 0usize;
    let mut seen_length = false;
    let mut count = 0usize;

    for line in lines {
        let line = strip_cr(line);
        if line.is_empty() {
            continue;
        }
        count += 1;
        if count > MAX_HEADERS {
            return Err(Status::PayloadTooLarge);
        }
        let colon = line
            .iter()
            .position(|b| *b == b':')
            .ok_or(Status::BadRequest)?;
        let name = std::str::from_utf8(&line[..colon])
            .map_err(|_| Status::BadRequest)?
            .trim()
            .to_ascii_lowercase();
        let value = std::str::from_utf8(&line[colon + 1..])
            .map_err(|_| Status::BadRequest)?
            .trim();

        match name.as_str() {
            // Rejected rather than parsed. A chunked body is the other half of
            // request smuggling, and this server has no use for one.
            "transfer-encoding" => return Err(Status::BadRequest),
            "content-length" => {
                // A second, differing `Content-Length` is the classic
                // desync. Two of them at all is a refusal.
                if seen_length {
                    return Err(Status::BadRequest);
                }
                seen_length = true;
                content_length = value.parse().map_err(|_| Status::BadRequest)?;
                if content_length > MAX_BODY {
                    return Err(Status::PayloadTooLarge);
                }
            }
            "authorization" => {
                bearer = value.strip_prefix("Bearer ").map(str::trim);
            }
            "origin" => origin = Some(value),
            "host" => host = Some(value),
            _ => {}
        }
    }

    let total = body_start + content_length;
    if buf.len() < total {
        return Ok(Err(Incomplete::NeedBody { total }));
    }

    Ok(Ok(Request {
        method,
        path,
        bearer,
        origin,
        host,
        body: &buf[body_start..total],
    }))
}

/// Splits `METHOD SP path SP version`.
fn parse_request_line(line: &[u8]) -> Result<(Method, String), Status> {
    let text = std::str::from_utf8(line).map_err(|_| Status::BadRequest)?;
    let mut parts = text.split(' ');
    let method = match parts.next().ok_or(Status::BadRequest)? {
        "GET" => Method::Get,
        "POST" => Method::Post,
        // Everything else, `HEAD` and `OPTIONS` included. Answering `OPTIONS`
        // is how a server accidentally grows CORS.
        _ => return Err(Status::MethodNotAllowed),
    };
    let target = parts.next().ok_or(Status::BadRequest)?;
    if parts.next().is_none() {
        return Err(Status::BadRequest);
    }
    // The query string is dropped before routing. Nothing here takes a query
    // parameter, and a token in one would land in every log and history file
    // that ever saw the URL.
    let path = target.split(['?', '#']).next().unwrap_or("/");
    let path = percent_decode(path)?;
    if !path.starts_with('/') || path.contains("..") {
        return Err(Status::BadRequest);
    }
    Ok((method, path))
}

/// Decodes `%XX` escapes.
///
/// Needed because identifiers in a path contain `:`, which every browser
/// percent-encodes — so a server that skips this rejects every request naming
/// one, and does it with a `400` that says nothing about why.
///
/// Refuses a malformed escape rather than passing it through: `%` followed by
/// something that is not two hex digits is not a path anyone meant to send, and
/// guessing at it is how a decoder ends up disagreeing with the one in front of
/// it.
fn percent_decode(path: &str) -> Result<String, Status> {
    if !path.contains('%') {
        return Ok(path.to_owned());
    }

    let raw = path.as_bytes();
    let mut out = Vec::with_capacity(raw.len());
    let mut at = 0;
    while at < raw.len() {
        if raw[at] == b'%' {
            let hex = raw.get(at + 1..at + 3).ok_or(Status::BadRequest)?;
            let text = std::str::from_utf8(hex).map_err(|_| Status::BadRequest)?;
            out.push(u8::from_str_radix(text, 16).map_err(|_| Status::BadRequest)?);
            at += 3;
        } else {
            out.push(raw[at]);
            at += 1;
        }
    }
    String::from_utf8(out).map_err(|_| Status::BadRequest)
}

/// Finds the blank line ending the header block.
fn find_head_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

/// Drops a trailing `\r`.
fn strip_cr(line: &[u8]) -> &[u8] {
    match line.split_last() {
        Some((b'\r', rest)) => rest,
        _ => line,
    }
}

/// Builds a complete response.
///
/// Every response carries the same hardening headers, because a header that is
/// conditional is a header that is missing on the path nobody tested.
#[must_use]
pub fn response(status: Status, content_type: &str, body: &[u8]) -> Vec<u8> {
    // No CORS headers, ever. Their absence is what stops a page on another
    // origin from reading a vault served on loopback.
    //
    // `no-store` because these responses carry memory content, and a browser
    // cache is a plaintext copy outside the vault (I1).
    //
    // The CSP allows inline script and style because the page is a single
    // self-contained file, and forbids every remote origin — so even if corpus
    // text ever reached the page as markup, it would have nowhere to send what
    // it read (THREAT_MODEL §T7).
    let head = format!(
        "HTTP/1.1 {}\r\n\
         Content-Type: {content_type}\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         Cache-Control: no-store\r\n\
         X-Content-Type-Options: nosniff\r\n\
         Referrer-Policy: no-referrer\r\n\
         Content-Security-Policy: default-src 'none'; \
script-src 'unsafe-inline'; style-src 'unsafe-inline'; \
connect-src 'self'; img-src 'self' data:; manifest-src 'self'; \
form-action 'none'; frame-ancestors 'none'; base-uri 'none'\r\n\
         \r\n",
        status.line(),
        body.len()
    );
    let mut out = head.into_bytes();
    out.extend_from_slice(body);
    out
}

/// A JSON error body that names the status and nothing else.
///
/// Deliberately content-free. An error carrying what was asked for would put
/// memory content in a response the caller was not allowed to have (I8).
#[must_use]
pub fn error_response(status: Status) -> Vec<u8> {
    refusal(status, "")
}

/// The same, plus the name of the rule that refused.
///
/// A status code alone makes two unrelated refusals indistinguishable — a
/// cross-origin request and a quest whose commitment does not verify are both
/// `403`, and a screen that guesses between them tells the user the wrong
/// thing. The `rule` names which check fired, never what was asked for, so it
/// stays as content-free as the status it accompanies (I8).
#[must_use]
pub fn refusal(status: Status, rule: &str) -> Vec<u8> {
    let body = if rule.is_empty() {
        format!("{{\"error\":\"{}\"}}", status.line())
    } else {
        format!("{{\"error\":\"{}\",\"rule\":\"{rule}\"}}", status.line())
    };
    response(status, "application/json; charset=utf-8", body.as_bytes())
}

/// Whether an `Origin` names the same origin as `Host`.
///
/// Browsers send `Origin` on **every** POST, not only cross-origin ones, so a
/// server that refuses any request carrying one refuses its own page's writes.
/// That failure is invisible from the outside: reads keep working and every
/// write silently 403s.
///
/// An absent `Origin` is same-origin by omission — that is a plain GET, or a
/// script or curl, neither of which a browser can be tricked into making on a
/// user's behalf. `Origin: null`, which a sandboxed frame sends, matches no
/// host and is refused.
#[must_use]
pub fn same_origin(origin: &str, host: Option<&str>) -> bool {
    let Some(host) = host.filter(|h| !h.is_empty()) else {
        return false;
    };
    origin
        .strip_prefix("http://")
        .or_else(|| origin.strip_prefix("https://"))
        .is_some_and(|named| named.eq_ignore_ascii_case(host))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn get(raw: &str) -> Result<Result<Request<'_>, Incomplete>, Status> {
        parse(raw.as_bytes())
    }

    #[test]
    fn a_plain_get_parses() {
        let r = get("GET /api/quests HTTP/1.1\r\nHost: x\r\n\r\n")
            .expect("accepted")
            .expect("complete");
        assert_eq!(r.method, Method::Get);
        assert_eq!(r.path, "/api/quests");
        assert!(r.body.is_empty());
    }

    #[test]
    fn a_bearer_token_is_read() {
        let r = get("GET / HTTP/1.1\r\nAuthorization: Bearer abc123\r\n\r\n")
            .expect("accepted")
            .expect("complete");
        assert_eq!(r.bearer, Some("abc123"));
    }

    #[test]
    fn header_names_are_case_insensitive() {
        let r = get("GET / HTTP/1.1\r\nAUTHORIZATION: Bearer abc\r\nOrIgIn: http://x\r\n\r\n")
            .expect("accepted")
            .expect("complete");
        assert_eq!(r.bearer, Some("abc"));
        assert_eq!(r.origin, Some("http://x"));
    }

    #[test]
    fn a_body_arrives_with_its_content_length() {
        let r = get("POST /a HTTP/1.1\r\nContent-Length: 5\r\n\r\nhello")
            .expect("accepted")
            .expect("complete");
        assert_eq!(r.method, Method::Post);
        assert_eq!(r.body, b"hello");
    }

    #[test]
    fn a_half_arrived_request_asks_for_more() {
        assert_eq!(
            get("GET / HTTP/1.1\r\nHost: x").expect("accepted"),
            Err(Incomplete::NeedMore)
        );
        // The total is derived rather than written down: a magic number here
        // would be a second, silent parser that could disagree with the real one.
        let head = "POST /a HTTP/1.1\r\nContent-Length: 5\r\n\r\n";
        assert_eq!(
            get(&format!("{head}hel")).expect("accepted"),
            Err(Incomplete::NeedBody {
                total: head.len() + 5
            })
        );
    }

    /// Request smuggling is two parsers disagreeing about where a message ends.
    /// Chunked encoding is rejected rather than parsed, so there is no second
    /// opinion to disagree with.
    #[test]
    fn a_chunked_request_is_refused() {
        assert_eq!(
            get("POST /a HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"),
            Err(Status::BadRequest)
        );
    }

    /// Two `Content-Length` headers is the classic desync, whether they agree
    /// or not.
    #[test]
    fn two_content_lengths_are_refused() {
        assert_eq!(
            get("POST /a HTTP/1.1\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\nhello"),
            Err(Status::BadRequest)
        );
        assert_eq!(
            get("POST /a HTTP/1.1\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\nhello"),
            Err(Status::BadRequest)
        );
    }

    /// Browsers attach `Origin` to every POST, so this decides whether the
    /// page's own writes work at all.
    #[test]
    fn same_origin_compares_the_whole_authority() {
        assert!(same_origin("http://127.0.0.1:7749", Some("127.0.0.1:7749")));
        assert!(same_origin(
            "https://box.local:7749",
            Some("box.local:7749")
        ));
        // Case in a hostname is not significant.
        assert!(same_origin("http://Box.Local:7749", Some("box.local:7749")));

        // A different port is a different origin, and a check on the hostname
        // alone would wave this through.
        assert!(!same_origin(
            "http://127.0.0.1:9999",
            Some("127.0.0.1:7749")
        ));
        assert!(!same_origin("https://evil.example", Some("127.0.0.1:7749")));
        // What a sandboxed frame sends.
        assert!(!same_origin("null", Some("127.0.0.1:7749")));
        // Nothing to compare against is not a match.
        assert!(!same_origin("http://127.0.0.1:7749", None));
        assert!(!same_origin("http://127.0.0.1:7749", Some("")));
        // A prefix of the real host is not the real host.
        assert!(!same_origin("http://127.0.0.1", Some("127.0.0.1:7749")));
    }

    #[test]
    fn a_host_header_is_read() {
        let r = get("GET / HTTP/1.1\r\nHost: 127.0.0.1:7749\r\n\r\n")
            .expect("accepted")
            .expect("complete");
        assert_eq!(r.host, Some("127.0.0.1:7749"));
    }

    #[test]
    fn an_unimplemented_method_is_refused() {
        for method in ["HEAD", "PUT", "DELETE", "OPTIONS", "TRACE"] {
            assert_eq!(
                get(&format!("{method} / HTTP/1.1\r\n\r\n")),
                Err(Status::MethodNotAllowed),
                "{method}"
            );
        }
    }

    #[test]
    fn a_query_string_is_dropped_before_routing() {
        let r = get("GET /api/quests?t=secret HTTP/1.1\r\n\r\n")
            .expect("accepted")
            .expect("complete");
        assert_eq!(r.path, "/api/quests");
    }

    /// Every browser percent-encodes the `:` in an identifier, so a server that
    /// skips this rejects every request naming one — with a `400` that says
    /// nothing about why.
    #[test]
    fn a_percent_encoded_path_is_decoded() {
        let r = get("POST /api/quests/qst%3Aabc123/answer HTTP/1.1\r\n\r\n")
            .expect("accepted")
            .expect("complete");
        assert_eq!(r.path, "/api/quests/qst:abc123/answer");
    }

    /// Decoding has to happen *before* the traversal check, or the check is
    /// looking at a string the router will never see.
    #[test]
    fn an_encoded_traversal_is_refused_too() {
        assert_eq!(
            get("GET /%2e%2e%2fetc/passwd HTTP/1.1\r\n\r\n"),
            Err(Status::BadRequest)
        );
    }

    #[test]
    fn a_malformed_escape_is_refused_rather_than_guessed_at() {
        for path in ["/a%", "/a%2", "/a%zz", "/a%2z"] {
            assert_eq!(
                get(&format!("GET {path} HTTP/1.1\r\n\r\n")),
                Err(Status::BadRequest),
                "{path}"
            );
        }
    }

    #[test]
    fn a_traversal_attempt_is_refused() {
        assert_eq!(
            get("GET /../../etc/passwd HTTP/1.1\r\n\r\n"),
            Err(Status::BadRequest)
        );
        assert_eq!(
            get("GET notapath HTTP/1.1\r\n\r\n"),
            Err(Status::BadRequest)
        );
    }

    #[test]
    fn an_oversized_body_is_refused_before_it_is_read() {
        let raw = format!(
            "POST /a HTTP/1.1\r\nContent-Length: {}\r\n\r\n",
            MAX_BODY + 1
        );
        assert_eq!(parse(raw.as_bytes()), Err(Status::PayloadTooLarge));
    }

    #[test]
    fn too_many_headers_are_refused() {
        let mut raw = String::from("GET / HTTP/1.1\r\n");
        for i in 0..(MAX_HEADERS + 1) {
            raw.push_str(&format!("X-{i}: v\r\n"));
        }
        raw.push_str("\r\n");
        assert_eq!(parse(raw.as_bytes()), Err(Status::PayloadTooLarge));
    }

    /// A client that never sends a blank line must not be able to make the
    /// server buffer without limit.
    #[test]
    fn an_endless_header_block_is_refused_rather_than_buffered() {
        let raw = vec![b'x'; MAX_REQUEST_LINE + MAX_HEADER_BYTES + 1];
        assert_eq!(parse(&raw), Err(Status::PayloadTooLarge));
    }

    #[test]
    fn a_malformed_header_is_refused() {
        assert_eq!(
            get("GET / HTTP/1.1\r\nnocolonhere\r\n\r\n"),
            Err(Status::BadRequest)
        );
    }

    #[test]
    fn a_request_line_without_a_version_is_refused() {
        assert_eq!(get("GET /\r\n\r\n"), Err(Status::BadRequest));
    }

    /// The policy has to permit the page's own furniture, or an installed copy
    /// loses its Home Screen icon and falls back to a screenshot. Caught by a
    /// browser rather than by reading: the icons are served from this origin,
    /// and `img-src data:` alone silently refused them.
    #[test]
    fn the_policy_allows_this_origin_and_no_other() {
        let text = String::from_utf8_lossy(&response(Status::Ok, "text/html", b"x")).into_owned();
        let policy = text
            .lines()
            .find(|l| l.starts_with("Content-Security-Policy:"))
            .expect("a policy");

        for allowed in [
            "img-src 'self'",
            "manifest-src 'self'",
            "connect-src 'self'",
        ] {
            assert!(policy.contains(allowed), "{allowed} missing from {policy}");
        }
        // Nothing remote, which is what makes the policy worth having: injected
        // corpus text would have nowhere to send what it read (§T7).
        assert!(!policy.contains("http://"), "{policy}");
        assert!(!policy.contains("https://"), "{policy}");
        assert!(policy.contains("default-src 'none'"), "{policy}");
    }

    /// No CORS headers, on any path. Their absence is what stops a page on
    /// another origin from reading a vault served on loopback.
    #[test]
    fn no_response_carries_a_cors_header() {
        for status in [Status::Ok, Status::Unauthorized, Status::ServerError] {
            let out = response(status, "application/json", b"{}");
            let text = String::from_utf8_lossy(&out).to_ascii_lowercase();
            assert!(!text.contains("access-control-"), "{status:?}");
        }
    }

    /// These responses carry memory content, and a browser cache is a plaintext
    /// copy outside the vault (I1).
    #[test]
    fn every_response_forbids_caching_and_sniffing() {
        for status in [Status::Ok, Status::NotFound, Status::ServerError] {
            let text = String::from_utf8_lossy(&response(status, "text/html", b"x")).into_owned();
            assert!(text.contains("Cache-Control: no-store"), "{status:?}");
            assert!(
                text.contains("X-Content-Type-Options: nosniff"),
                "{status:?}"
            );
            assert!(text.contains("Connection: close"), "{status:?}");
        }
    }

    /// An error body that repeated what was asked for would put memory content
    /// in a response the caller was not allowed to have (I8).
    #[test]
    fn an_error_body_says_nothing_about_the_request() {
        let text = String::from_utf8_lossy(&error_response(Status::NotFound)).into_owned();
        assert!(text.contains("404 Not Found"));
        assert_eq!(text.matches("404").count(), 2, "status line and body only");
    }

    #[test]
    fn the_content_length_matches_the_body() {
        let out = response(Status::Ok, "application/json", b"{\"a\":1}");
        let text = String::from_utf8_lossy(&out).into_owned();
        assert!(text.contains("Content-Length: 7"));
        assert!(text.ends_with("{\"a\":1}"));
    }
}
