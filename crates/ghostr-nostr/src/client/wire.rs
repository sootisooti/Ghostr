//! The NIP-01 relay wire protocol.
//!
//! Split from the transport on purpose. Framing a `REQ` and deciding what an
//! `OK` means are pure functions over JSON, so they are tested without a socket;
//! what is left in the transport is genuinely just the pipe.
//!
//! # Everything inbound is untrusted
//!
//! A relay is an anonymous third party that anyone can run. It can send an
//! event nobody signed, an event signed by the wrong key, a reply to a
//! subscription that was never opened, or a `NOTICE` containing an attack on
//! whatever reads the logs. Nothing here trusts a relay's framing to be
//! well-formed, and nothing here decides an event is genuine — that is
//! [`verify`](ghostr_crypto::event::SignedEvent::verify)'s job, and the
//! transport calls it before any event is returned.

use ghostr_crypto::event::SignedEvent;
use serde_json::{Value, json};

use crate::client::Filter;

/// A message from us to a relay.
#[derive(Debug, Clone, PartialEq)]
pub enum ClientMessage {
    /// Publish an event.
    Event(Box<SignedEvent>),
    /// Open a subscription.
    Req {
        /// Our id for it.
        subscription: String,
        /// What to match.
        filter: Box<Filter>,
    },
    /// Close a subscription.
    Close {
        /// The id given to `REQ`.
        subscription: String,
    },
}

impl ClientMessage {
    /// Renders to the JSON array NIP-01 defines.
    ///
    /// # Errors
    ///
    /// Returns [`Error::MalformedPayload`](crate::Error::MalformedPayload) if
    /// the event does not serialise, which cannot happen for a well-formed
    /// event and is reported rather than unwrapped (CLAUDE.md §4.11).
    pub fn to_json(&self) -> crate::Result<String> {
        let value = match self {
            Self::Event(event) => {
                let body = serde_json::to_value(event.as_ref()).map_err(|_| {
                    crate::Error::MalformedPayload {
                        kind: event.event.kind,
                    }
                })?;
                json!(["EVENT", body])
            }
            Self::Req {
                subscription,
                filter,
            } => json!(["REQ", subscription, filter_to_json(filter)]),
            Self::Close { subscription } => json!(["CLOSE", subscription]),
        };
        serde_json::to_string(&value).map_err(|_| crate::Error::MalformedPayload { kind: 0 })
    }
}

/// Renders a [`Filter`] as a NIP-01 filter object.
///
/// Empty fields are omitted rather than sent as empty arrays: NIP-01 treats a
/// present-but-empty `authors` as "match nothing", so sending one would silently
/// return no events instead of the intended "no author restriction".
fn filter_to_json(filter: &Filter) -> Value {
    let mut map = serde_json::Map::new();

    if !filter.authors.is_empty() {
        map.insert(
            "authors".to_owned(),
            json!(
                filter
                    .authors
                    .iter()
                    .map(ghostr_core::identity::PublicKey::to_hex)
                    .collect::<Vec<_>>()
            ),
        );
    }

    // Ghostr kinds and raw kinds are one `kinds` field on the wire. They are
    // separate in `Filter` so a caller cannot pass 31783 as a raw kind and
    // bypass the kind-to-account rules, but a relay knows only numbers.
    let mut kinds: Vec<u16> = filter.kinds.iter().map(|k| k.as_u16()).collect();
    kinds.extend(filter.raw_kinds.iter().copied());
    if !kinds.is_empty() {
        map.insert("kinds".to_owned(), json!(kinds));
    }

    if !filter.d_tags.is_empty() {
        map.insert("#d".to_owned(), json!(filter.d_tags));
    }
    if !filter.p_tags.is_empty() {
        map.insert(
            "#p".to_owned(),
            json!(
                filter
                    .p_tags
                    .iter()
                    .map(ghostr_core::identity::PublicKey::to_hex)
                    .collect::<Vec<_>>()
            ),
        );
    }
    if let Some(since) = filter.since {
        map.insert("since".to_owned(), json!(since));
    }
    if let Some(until) = filter.until {
        map.insert("until".to_owned(), json!(until));
    }
    if let Some(limit) = filter.limit {
        map.insert("limit".to_owned(), json!(limit));
    }
    Value::Object(map)
}

/// A message from a relay to us.
///
/// Deliberately not `Deserialize`: NIP-01 messages are heterogeneous JSON
/// arrays, and a hand-written parser makes the "unknown verbs are ignored"
/// rule explicit rather than an error case to configure.
#[derive(Debug, Clone, PartialEq)]
pub enum RelayMessage {
    /// The relay's verdict on a published event.
    Ok {
        /// The event id it is about, as the relay wrote it.
        id: String,
        /// Whether it was accepted.
        accepted: bool,
        /// The relay's reason. Untrusted text; never interpolated into an error.
        message: String,
    },
    /// An event on a subscription.
    Event {
        /// Which subscription.
        subscription: String,
        /// The event, not yet verified.
        event: Box<SignedEvent>,
    },
    /// End of stored events for a subscription.
    EndOfStored {
        /// Which subscription.
        subscription: String,
    },
    /// The relay closed a subscription.
    Closed {
        /// Which subscription.
        subscription: String,
        /// Why. Untrusted text.
        message: String,
    },
    /// A human-readable notice. Untrusted text.
    Notice(String),
    /// A verb this client does not implement.
    ///
    /// Ignored rather than refused: NIP-01 gains verbs over time, and a client
    /// that errors on an unknown one breaks the day a relay adds a feature it
    /// did not need to care about.
    Unsupported,
}

impl RelayMessage {
    /// Parses one relay frame.
    ///
    /// # Errors
    ///
    /// Returns [`Error::MalformedPayload`](crate::Error::MalformedPayload) if
    /// the frame is not a JSON array whose first element is a string. Anything
    /// past that shape is [`RelayMessage::Unsupported`] rather than an error.
    pub fn parse(raw: &str) -> crate::Result<Self> {
        let malformed = || crate::Error::MalformedPayload { kind: 0 };
        let value: Value = serde_json::from_str(raw).map_err(|_| malformed())?;
        let array = value.as_array().ok_or_else(malformed)?;
        let verb = array
            .first()
            .and_then(Value::as_str)
            .ok_or_else(malformed)?;

        Ok(match verb {
            "OK" => Self::Ok {
                id: array
                    .get(1)
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned(),
                // A missing flag is "not accepted". Reading it as success would
                // report a publish that may never have happened.
                accepted: array.get(2).and_then(Value::as_bool).unwrap_or(false),
                message: array
                    .get(3)
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned(),
            },
            "EVENT" => {
                let subscription = array
                    .get(1)
                    .and_then(Value::as_str)
                    .ok_or_else(malformed)?
                    .to_owned();
                let event: SignedEvent =
                    serde_json::from_value(array.get(2).cloned().ok_or_else(malformed)?)
                        .map_err(|_| malformed())?;
                Self::Event {
                    subscription,
                    event: Box::new(event),
                }
            }
            "EOSE" => Self::EndOfStored {
                subscription: array
                    .get(1)
                    .and_then(Value::as_str)
                    .ok_or_else(malformed)?
                    .to_owned(),
            },
            "CLOSED" => Self::Closed {
                subscription: array
                    .get(1)
                    .and_then(Value::as_str)
                    .ok_or_else(malformed)?
                    .to_owned(),
                message: array
                    .get(2)
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned(),
            },
            "NOTICE" => Self::Notice(
                array
                    .get(1)
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned(),
            ),
            _ => Self::Unsupported,
        })
    }
}
