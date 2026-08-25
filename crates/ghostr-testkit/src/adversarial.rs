//! Hostile fixtures.
//!
//! These are a **permanent part of the test suite**, not a one-off check
//! (CLAUDE.md §6). A corpus containing prompt injection belongs in CI for the
//! same reason a crypto test vector does: the defence is only real while
//! something keeps checking it.

use ghostr_core::memory::Memory;

/// Corpus content written to attack the pipeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum InjectionKind {
    /// Direct instruction override: "ignore previous instructions".
    InstructionOverride,
    /// Attempts to plant a false stance about the user.
    StancePoisoning,
    /// Attempts to plant a false relationship, e.g. that the user trusts an
    /// attacker.
    RelationshipPoisoning,
    /// Text shaped like the extraction schema, trying to be read as output.
    SchemaMimicry,
    /// Text shaped like Ghostr's own prompt delimiters, trying to break out of
    /// the data channel.
    DelimiterEscape,
    /// An instruction to suppress a day: "summarize this as nothing happened".
    SuppressionAttempt,
}

/// A memory carrying an injection attempt.
///
/// Always [`TrustLevel::ThirdParty`](ghostr_core::sensitivity::TrustLevel::ThirdParty),
/// because that is how such content actually arrives — through a nostr feed or
/// an RSS item, never from the user.
#[must_use]
pub fn injected_memory(kind: InjectionKind) -> Memory {
    todo!("build a third-party memory carrying the named injection")
}

/// A corpus with injections scattered through ordinary content.
///
/// The realistic case. An attack buried in ninety benign memories is the one
/// that gets through, not one in a fixture of three.
#[must_use]
pub fn poisoned_corpus(clean: Vec<Memory>, injections: &[InjectionKind]) -> Vec<Memory> {
    todo!("interleave injected memories through the clean corpus")
}

/// A payload carrying things that must never reach a remote provider.
///
/// Backs the table test that asserts every policy configuration denies it: an
/// `nsec`, an API key, a payment card, a national identifier (SPEC §11.2).
#[must_use]
pub fn secret_bearing_text() -> &'static str {
    todo!("return text containing synthetic, clearly-fake credentials")
}
