//! This crate's error type.

/// Result alias for this crate.
pub type Result<T, E = Error> = core::result::Result<T, E>;

/// Something went wrong talking to a relay or decoding an event.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// No relay accepted the event.
    #[error("no relay accepted the event ({attempted} attempted)")]
    PublishRejected {
        /// How many relays were tried.
        attempted: u32,
    },

    /// A relay could not be reached.
    #[error("relay unreachable: {relay}")]
    Unreachable {
        /// Which relay.
        relay: String,
    },

    /// An event did not decode into the expected Ghostr payload.
    #[error("event does not decode as kind {kind}")]
    MalformedPayload {
        /// The kind that was expected.
        kind: u16,
    },

    /// A payload was encoded under an account SPEC §8.1 does not assign to it.
    ///
    /// The dangerous direction is an anchor receipt under the identity key: the
    /// event is well formed, a relay accepts it, and it quietly links a chain to
    /// the identity the separate anchor account exists to keep apart.
    #[error("kind {kind} must be signed by a different account (SPEC §8.1)")]
    WrongSigningAccount {
        /// The kind that was being encoded.
        kind: u16,
    },

    /// An event was not one of Ghostr's kinds, or not addressed by a Ghostr
    /// `d` tag, so it has no NIP-78 mirror.
    #[error("kind {kind} has no NIP-78 mirror")]
    NotMirrorable {
        /// The kind that was offered.
        kind: u16,
    },

    /// A ghost note was built with no text.
    ///
    /// An empty note is not a note; publishing one would emit disclosure tags
    /// attached to nothing.
    #[error("ghost note has no content")]
    EmptyNote,

    /// An event's signature or id did not verify.
    ///
    /// Relay-supplied events are untrusted input. Verifying before decoding is
    /// not optional.
    #[error("event failed signature verification")]
    BadSignature,

    /// A ghost-authored event was missing its disclosure tags (SPEC I10).
    ///
    /// Unreachable through the builder API, which cannot construct one without
    /// them. The variant exists for events arriving *from* a relay, where a
    /// third party may have published something claiming to be a ghost without
    /// disclosing it.
    #[error("ghost-authored event is missing its disclosure tags")]
    MissingDisclosure,

    /// A publish was attempted while publishing is disabled.
    ///
    /// The default state. Publishing is opt-in per scope and this is what
    /// enforces it at the last moment before bytes move.
    #[error("publishing is disabled for scope `{scope}`")]
    PublishingDisabled {
        /// Which scope was attempted.
        scope: String,
    },

    /// A `bunker://` URL did not parse.
    ///
    /// Carries no detail on purpose: the URL contains a connection secret, and
    /// an error quoting the input would put it in a log.
    #[error("malformed bunker:// url")]
    MalformedBunkerUrl,

    /// Encryption or signing failed.
    #[error("crypto error")]
    Crypto(#[from] ghostr_crypto::Error),
}
