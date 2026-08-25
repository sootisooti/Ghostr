//! This crate's error type.

/// Result alias for this crate.
pub type Result<T, E = Error> = core::result::Result<T, E>;

/// Something went wrong calling a model, or the egress gate refused.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The egress policy refused to let this payload leave the device.
    ///
    /// Not an exceptional condition. The most common cause is the system working
    /// correctly — `Secret` content was routed at a remote model — so callers
    /// should fall back to a local model rather than surfacing a failure.
    #[error("egress denied: {reason}")]
    EgressDenied {
        /// Why, in terms a user can act on.
        reason: crate::egress::DenyReason,
    },

    /// A provider was asked for but is not compiled into this build.
    ///
    /// Provider features are off by default, so a stock build cannot egress at
    /// all. Reaching this means configuration expects a capability the binary
    /// does not have.
    #[error("provider `{provider}` is not enabled in this build")]
    ProviderNotEnabled {
        /// The provider named in configuration.
        provider: String,
    },

    /// The model returned output that did not validate against the schema.
    ///
    /// The extraction path retries once and then drops the cluster, marking it
    /// unresolved. Prose that will not parse is discarded rather than
    /// interpreted, which is the structural half of the prompt-injection defence
    /// (THREAT_MODEL §T7).
    #[error("model output failed schema validation")]
    SchemaViolation,

    /// The model could not be reached.
    #[error("model transport failed: {reason}")]
    Transport {
        /// What failed, in transport terms. Never carries payload content.
        reason: String,
    },

    /// The prompt did not fit the model's context window.
    #[error("prompt exceeds context window: {tokens} > {limit}")]
    ContextOverflow {
        /// Tokens the prompt needed.
        tokens: u32,
        /// Tokens the model allows.
        limit: u32,
    },

    /// The provider rate-limited or refused the request.
    #[error("provider refused the request: {status}")]
    ProviderRefused {
        /// Provider status, e.g. an HTTP status or a named error.
        status: String,
    },

    /// The egress log could not be written.
    ///
    /// **Fails the call.** If the audit record cannot be written the request must
    /// not proceed: an unlogged egress is exactly the thing the user was promised
    /// could not happen, and silently degrading to "sent but unrecorded" would
    /// make the log useless as evidence (SPEC I5).
    #[error("egress log write failed; request refused")]
    EgressLogUnavailable,
}
