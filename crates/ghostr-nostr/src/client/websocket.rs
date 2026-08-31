//! A [`RelayClient`] over blocking websockets.
//!
//! # Why blocking
//!
//! Every other I/O path in this workspace is blocking — `ureq` for anchoring
//! and inference, `std::net` plus threads for `serve` — and `tokio` is pulled
//! with `rt` alone, explicitly without a reactor. A relay client is a handful of
//! connections, not thousands, so a thread each costs nothing and an async
//! runtime would be the single largest dependency in the tree, added for
//! concurrency this workload does not have.
//!
//! [`RelayClient`]'s methods stay `async` because that is the seam: the trait
//! describes what talking to relays *is*, and a future implementation may be
//! asynchronous. The futures here simply never yield, exactly as
//! `ghostr-llm`'s `ureq`-backed providers already do.
//!
//! # What a relay is
//!
//! An anonymous third party anyone can run. It sees connection metadata, it
//! chooses what to return, and it can return anything at all. Two rules follow,
//! and both are enforced here rather than left to callers:
//!
//! 1. **Every inbound event is verified before it is returned.** A relay that
//!    serves an event nobody signed, or one signed by a different key, gets its
//!    answer dropped. An unverified event reaching the decoder is a forged
//!    manifest treated as real.
//! 2. **Publishing is refused unless the scope is enabled.** The default is that
//!    nothing publishes.

use std::collections::HashSet;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

use async_trait::async_trait;
use ghostr_crypto::event::SignedEvent;
use tungstenite::client::IntoClientRequest;
use tungstenite::{Message, WebSocket, stream::MaybeTlsStream};

use crate::client::wire::{ClientMessage, RelayMessage};
use crate::client::{Filter, PublishReport, PublishScope, RelayClient, Subscription};

/// How long to wait on a relay before giving up on it.
///
/// A relay that accepts a connection and then says nothing must not hold the
/// whole publish. Applied per socket read, so a slow relay is dropped from a
/// publish without affecting the others.
const RELAY_TIMEOUT: Duration = Duration::from_secs(10);

/// How many frames to read while waiting for one answer.
///
/// A relay may interleave `NOTICE`s and events from other subscriptions with the
/// reply we want. Bounded so a relay that streams forever cannot pin a thread.
const MAX_FRAMES_PER_WAIT: usize = 256;

/// A relay client over blocking websockets.
pub struct WebsocketRelayClient {
    relays: Vec<String>,
    enabled: HashSet<PublishScope>,
}

impl core::fmt::Debug for WebsocketRelayClient {
    /// Relay URLs are configuration, not secrets, but the scope set says what
    /// this vault is willing to publish, so it is summarised rather than listed.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("WebsocketRelayClient")
            .field("relays", &self.relays.len())
            .field("enabled_scopes", &self.enabled.len())
            .finish()
    }
}

impl WebsocketRelayClient {
    /// Builds a client for a relay set.
    ///
    /// `enabled` is the set of scopes this vault may publish. Anything not named
    /// is refused, so the empty set — the default a fresh vault has — publishes
    /// nothing at all.
    #[must_use]
    pub fn new(relays: Vec<String>, enabled: HashSet<PublishScope>) -> Self {
        Self { relays, enabled }
    }

    /// Whether a scope may be published.
    ///
    /// [`PublishScope::Revocation`] is always permitted. A revocation the user
    /// cannot publish because they disabled publishing is a revocation that does
    /// not happen, and the whole point of one is that it works when things have
    /// gone wrong.
    fn permits(&self, scope: PublishScope) -> bool {
        scope == PublishScope::Revocation || self.enabled.contains(&scope)
    }

    /// Opens one relay connection.
    ///
    /// # The timeouts are set before the handshake, deliberately
    ///
    /// `tungstenite::connect` performs the HTTP upgrade itself, which means it
    /// *reads* before it returns. Setting a read timeout on the socket it hands
    /// back is therefore too late: a relay that completes the TCP connection and
    /// then says nothing at all holds the thread inside the handshake, where no
    /// timeout of ours applies. So the stream is built here, given its deadlines,
    /// and only then handed over.
    ///
    /// `a_stalled_relay_does_not_hang_the_publish` is what holds this to
    /// account; with the timeouts set after the handshake it hangs for as long
    /// as the relay cares to wait.
    fn connect(relay: &str) -> crate::Result<WebSocket<MaybeTlsStream<TcpStream>>> {
        let unreachable = || crate::Error::Unreachable {
            relay: relay.to_owned(),
        };

        let request = relay.into_client_request().map_err(|_| unreachable())?;
        let uri = request.uri().clone();
        let host = uri.host().ok_or_else(unreachable)?;
        let port = uri.port_u16().unwrap_or(match uri.scheme_str() {
            Some("wss") => 443,
            _ => 80,
        });

        // DNS resolution is not covered by these timeouts — the resolver has its
        // own, and `std` exposes no hook for it. A relay whose name does not
        // resolve fails here rather than hanging, which is the case that matters.
        let address = (host, port)
            .to_socket_addrs()
            .map_err(|_| unreachable())?
            .next()
            .ok_or_else(unreachable)?;

        let stream =
            TcpStream::connect_timeout(&address, RELAY_TIMEOUT).map_err(|_| unreachable())?;
        stream
            .set_read_timeout(Some(RELAY_TIMEOUT))
            .map_err(|_| unreachable())?;
        stream
            .set_write_timeout(Some(RELAY_TIMEOUT))
            .map_err(|_| unreachable())?;

        let (socket, _response) =
            tungstenite::client_tls(request, stream).map_err(|_| unreachable())?;
        Ok(socket)
    }

    /// Reads frames until `wanted` returns a value, or the budget runs out.
    fn wait_for<S, T>(
        socket: &mut WebSocket<S>,
        mut wanted: impl FnMut(RelayMessage) -> Option<T>,
    ) -> Option<T>
    where
        S: Read + Write,
    {
        for _ in 0..MAX_FRAMES_PER_WAIT {
            let Ok(message) = socket.read() else {
                return None;
            };
            let text = match message {
                Message::Text(text) => text.to_string(),
                Message::Close(_) => return None,
                // Ping/Pong are handled by tungstenite; anything else is not a
                // NIP-01 frame and is skipped rather than treated as an answer.
                _ => continue,
            };
            // A frame we cannot parse is the relay's problem, not a reason to
            // abandon the ones after it.
            let Ok(parsed) = RelayMessage::parse(&text) else {
                continue;
            };
            if let Some(found) = wanted(parsed) {
                return Some(found);
            }
        }
        None
    }
}

/// One relay's answer to a publish.
enum RelayVerdict {
    Accepted,
    Rejected(String),
    Unreachable,
}

impl WebsocketRelayClient {
    /// Publishes to a single relay and waits for its `OK`.
    fn publish_one(relay: &str, event: &SignedEvent, frame: &str) -> RelayVerdict {
        let Ok(mut socket) = Self::connect(relay) else {
            return RelayVerdict::Unreachable;
        };
        if socket.send(Message::text(frame.to_owned())).is_err() {
            return RelayVerdict::Unreachable;
        }

        let wanted = event.id.to_hex();
        let verdict = Self::wait_for(&mut socket, |message| match message {
            // The id is matched before the verdict is believed. A relay
            // answering about a different event — its own earlier reply, or
            // another client's — would otherwise be read as this publish's
            // outcome.
            RelayMessage::Ok {
                id,
                accepted,
                message: reason,
            } if id == wanted => Some((accepted, reason)),
            _ => None,
        });
        let _ = socket.close(None);

        match verdict {
            Some((true, _)) => RelayVerdict::Accepted,
            Some((false, reason)) => RelayVerdict::Rejected(reason),
            None => RelayVerdict::Unreachable,
        }
    }
}

#[async_trait]
impl RelayClient for WebsocketRelayClient {
    async fn publish(
        &self,
        event: SignedEvent,
        scope: PublishScope,
    ) -> crate::Result<PublishReport> {
        if !self.permits(scope) {
            return Err(crate::Error::PublishingDisabled {
                scope: format!("{scope:?}"),
            });
        }

        // Verified before it leaves. An event this vault cannot itself verify is
        // one it must not ask the network to store.
        event.verify()?;
        let frame = ClientMessage::Event(Box::new(event.clone())).to_json()?;

        let mut report = PublishReport {
            accepted: Vec::new(),
            rejected: Vec::new(),
            unreachable: Vec::new(),
        };
        for relay in &self.relays {
            match Self::publish_one(relay, &event, &frame) {
                RelayVerdict::Accepted => report.accepted.push(relay.clone()),
                RelayVerdict::Rejected(reason) => {
                    report.rejected.push((relay.clone(), reason));
                }
                RelayVerdict::Unreachable => report.unreachable.push(relay.clone()),
            }
        }

        // One acceptance is success. Relays are individually unreliable and
        // collectively fine, and treating a single rejection as failure would
        // make publishing flaky for no gain.
        if report.accepted.is_empty() {
            return Err(crate::Error::PublishRejected {
                // Saturating rather than `as`: a relay list long enough to
                // overflow a u32 is absurd, but a silent wrap in a count the
                // user reads is worse than a clamp.
                attempted: u32::try_from(self.relays.len()).unwrap_or(u32::MAX),
            });
        }
        Ok(report)
    }

    async fn fetch(&self, filter: &Filter) -> crate::Result<Vec<SignedEvent>> {
        let subscription = "ghostr-fetch".to_owned();
        let request = ClientMessage::Req {
            subscription: subscription.clone(),
            filter: Box::new(filter.clone()),
        }
        .to_json()?;

        let mut collected: Vec<SignedEvent> = Vec::new();
        let mut reached_any = false;

        for relay in &self.relays {
            let Ok(mut socket) = Self::connect(relay) else {
                continue;
            };
            if socket.send(Message::text(request.clone())).is_err() {
                continue;
            }
            reached_any = true;

            let mut from_this_relay: Vec<SignedEvent> = Vec::new();
            Self::wait_for(&mut socket, |message| match message {
                RelayMessage::Event {
                    subscription: sub,
                    event,
                } if sub == subscription => {
                    // The rule the trait states, enforced here: a relay is
                    // untrusted, so an event that does not verify is dropped
                    // rather than returned. `verify` checks both that the id
                    // matches the body and that the signature matches the id,
                    // so a relay cannot alter content or borrow a signature.
                    if event.verify().is_ok() {
                        from_this_relay.push(*event);
                    }
                    None::<()>
                }
                RelayMessage::EndOfStored { subscription: sub } if sub == subscription => Some(()),
                RelayMessage::Closed {
                    subscription: sub, ..
                } if sub == subscription => Some(()),
                _ => None,
            });

            let _ = socket.send(Message::text(
                ClientMessage::Close {
                    subscription: subscription.clone(),
                }
                .to_json()?,
            ));
            let _ = socket.close(None);
            collected.extend(from_this_relay);
        }

        if !reached_any && !self.relays.is_empty() {
            return Err(crate::Error::Unreachable {
                relay: self.relays.join(", "),
            });
        }

        // The same event from several relays is one event. Deduplicated by id,
        // which is a hash of the body, so two copies with one id are one event
        // by construction.
        collected.sort_by_key(|event| event.id.to_hex());
        collected.dedup_by_key(|event| event.id.to_hex());
        Ok(collected)
    }

    async fn subscribe(&self, filter: Filter) -> crate::Result<Box<dyn Subscription>> {
        let subscription = "ghostr-sub".to_owned();
        let request = ClientMessage::Req {
            subscription: subscription.clone(),
            filter: Box::new(filter),
        }
        .to_json()?;

        // One relay, not all of them: a live subscription is a long-lived
        // connection, and fanning out would multiply both threads and the
        // duplicate events the caller has to reconcile.
        for relay in &self.relays {
            let Ok(mut socket) = Self::connect(relay) else {
                continue;
            };
            if socket.send(Message::text(request.clone())).is_err() {
                continue;
            }
            return Ok(Box::new(WebsocketSubscription {
                socket,
                subscription,
                closed: false,
            }));
        }
        Err(crate::Error::Unreachable {
            relay: self.relays.join(", "),
        })
    }
}

/// A live subscription over one relay connection.
struct WebsocketSubscription {
    socket: WebSocket<MaybeTlsStream<TcpStream>>,
    subscription: String,
    closed: bool,
}

#[async_trait]
impl Subscription for WebsocketSubscription {
    async fn next(&mut self) -> crate::Result<Option<SignedEvent>> {
        if self.closed {
            return Ok(None);
        }
        let wanted = self.subscription.clone();
        let found = WebsocketRelayClient::wait_for(&mut self.socket, |message| match message {
            // Verified here too. A subscription is the same untrusted channel a
            // fetch is, and the caller must not have to remember which one
            // checked.
            RelayMessage::Event {
                subscription: sub,
                event,
            } if sub == wanted && event.verify().is_ok() => Some(Some(*event)),
            RelayMessage::Closed {
                subscription: sub, ..
            } if sub == wanted => Some(None),
            _ => None,
        });

        match found {
            Some(Some(event)) => Ok(Some(event)),
            // Both a `CLOSED` and a timeout end the stream. A subscription whose
            // relay has gone quiet is over as far as the caller is concerned.
            Some(None) | None => {
                self.closed = true;
                Ok(None)
            }
        }
    }

    async fn close(&mut self) {
        if self.closed {
            return;
        }
        self.closed = true;
        if let Ok(frame) = (ClientMessage::Close {
            subscription: self.subscription.clone(),
        })
        .to_json()
        {
            let _ = self.socket.send(Message::text(frame));
        }
        let _ = self.socket.close(None);
    }
}
