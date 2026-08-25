//! How exposed a piece of content may be, and how much a source is trusted.
//!
//! [`Sensitivity`] is the most load-bearing enum in the system. It is assigned
//! at ingest, may only ever be *raised* by later processing, and is read at the
//! egress boundary to decide what a remote model is allowed to see (SPEC §11.2).

use serde::{Deserialize, Serialize};

/// How exposed a piece of content is allowed to be.
///
/// Ordering is meaningful and deliberate: `Public < Private < Secret`. Combining
/// two memories takes the *maximum* of their sensitivities, so a derived
/// artefact is never less protected than its most protected input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Sensitivity {
    /// Already public: the user published it themselves.
    Public,
    /// Ordinary private content. May egress *redacted*, if the user opts in.
    Private,
    /// Never egresses, under any policy, with no override. Local models only.
    ///
    /// There is deliberately no flag that relaxes this. A setting that lets
    /// `Secret` reach a provider is a setting that will eventually be on.
    Secret,
}

impl Sensitivity {
    /// The more restrictive of two levels.
    ///
    /// Use this everywhere sensitivities combine. Sensitivity ratchets up and
    /// never down.
    #[must_use]
    pub fn max(self, other: Self) -> Self {
        if self >= other { self } else { other }
    }

    /// Whether content at this level may ever reach a non-local model.
    ///
    /// A `true` here is necessary but not sufficient: the egress policy still
    /// evaluates provider configuration, redaction, and secret detection.
    #[must_use]
    pub fn may_egress(self) -> bool {
        matches!(self, Self::Public | Self::Private)
    }
}

/// How much weight a source's content carries, and whether it is hostile input.
///
/// This is a security control, not a quality signal.
/// [`TrustLevel::ThirdParty`] marks text written by someone other than the user,
/// which is the prompt-injection surface (THREAT_MODEL §T7): it may be
/// summarised and referenced, but it never becomes a voice exemplar and never
/// sources a claim about what the user believes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustLevel {
    /// The user authored it. The only level eligible to be a voice exemplar.
    FirstParty,
    /// The user asserted it about themselves after the fact.
    SelfReported,
    /// Someone else wrote it. Treated as untrusted input throughout.
    ThirdParty,
}

impl TrustLevel {
    /// Whether content at this level may be used as a voice exemplar.
    #[must_use]
    pub fn may_be_exemplar(self) -> bool {
        matches!(self, Self::FirstParty)
    }

    /// Whether content at this level may source a [`Stance`](crate::persona::Stance).
    #[must_use]
    pub fn may_source_stance(self) -> bool {
        matches!(self, Self::FirstParty | Self::SelfReported)
    }
}
