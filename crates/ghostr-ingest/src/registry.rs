//! Adapter lookup.

use ghostr_core::sensitivity::{Sensitivity, TrustLevel};
use ghostr_core::source::SourceKindTag;

use crate::adapter::IngestAdapter;

/// Maps source kinds to the adapters compiled into this build.
///
/// Feature-gated adapters mean a source kind can be *configured* but not
/// *available*, which is a real state a user hits after switching builds. It
/// surfaces as [`Error::NoAdapter`](crate::Error::NoAdapter) rather than as a
/// silently skipped sync — a source that stops producing memories without
/// saying so is the worst possible failure mode for a memory system.
#[derive(Default)]
pub struct AdapterRegistry {
    adapters: Vec<Box<dyn IngestAdapter>>,
}

impl core::fmt::Debug for AdapterRegistry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AdapterRegistry")
            .field("kinds", &self.available_kinds())
            .finish()
    }
}

impl AdapterRegistry {
    /// An empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// A registry with every adapter this build enables.
    ///
    /// The clock and entropy source are passed in rather than reached for:
    /// nothing outside the composition root calls `SystemTime::now` or `OsRng`,
    /// which is what makes an ingest run reproducible under a fake clock
    /// (ARCHITECTURE §4.7).
    #[must_use]
    pub fn with_builtins(
        clock: std::sync::Arc<dyn ghostr_core::time::Clock>,
        rng: std::sync::Arc<dyn ghostr_core::time::Rng>,
    ) -> Self {
        let mut registry = Self::default();
        #[cfg(feature = "markdown")]
        registry.register(Box::new(crate::markdown::MarkdownAdapter::new(
            std::sync::Arc::clone(&clock),
            std::sync::Arc::clone(&rng),
        )));
        #[cfg(feature = "journal")]
        registry.register(Box::new(crate::journal::JournalAdapter));
        #[cfg(feature = "structlog")]
        registry.register(Box::new(crate::structlog::StructLogAdapter::new(
            std::sync::Arc::clone(&clock),
            std::sync::Arc::clone(&rng),
        )));
        let _ = (clock, rng);
        registry
    }

    /// Adds an adapter, replacing any already registered for the same kind.
    ///
    /// Replacing rather than rejecting so a caller can substitute a fake in a
    /// test without the registry needing a second constructor. The builtins are
    /// registered once each, so this cannot silently shadow one of them.
    pub fn register(&mut self, adapter: Box<dyn IngestAdapter>) {
        let kind = adapter.kind();
        self.adapters.retain(|existing| existing.kind() != kind);
        self.adapters.push(adapter);
    }

    /// Looks up the adapter for a kind.
    #[must_use]
    pub fn get(&self, kind: SourceKindTag) -> Option<&dyn IngestAdapter> {
        self.adapters
            .iter()
            .find(|a| a.kind() == kind)
            .map(AsRef::as_ref)
    }

    /// Every source kind this build can ingest.
    ///
    /// Backs `ghostr source add --help`, so the list a user sees is the list
    /// that actually works.
    #[must_use]
    pub fn available_kinds(&self) -> Vec<SourceKindTag> {
        self.adapters.iter().map(|a| a.kind()).collect()
    }

    /// What adding a source of this kind would mean, for the confirmation
    /// `ghostr source add` shows.
    ///
    /// Surfacing "this will talk to the internet" and "this is somebody else's
    /// text" at the moment of the decision, rather than leaving them to be
    /// discovered afterwards.
    #[must_use]
    pub fn describe(&self, kind: SourceKindTag) -> Option<AdapterDescription> {
        let adapter = self.get(kind)?;
        Some(AdapterDescription {
            kind,
            trust: adapter.default_trust(),
            sensitivity: adapter.default_sensitivity(),
            touches_network: adapter.touches_network(),
        })
    }
}

/// What a user is agreeing to when they add a source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdapterDescription {
    /// Which kind.
    pub kind: SourceKindTag,
    /// How its content will be trusted.
    pub trust: TrustLevel,
    /// The sensitivity it suggests.
    pub sensitivity: Sensitivity,
    /// Whether pulling reaches the network.
    pub touches_network: bool,
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use ghostr_core::time::{Clock, Rng, Timestamp};

    use super::*;

    struct Fixed;
    impl Clock for Fixed {
        fn now(&self) -> Timestamp {
            Timestamp::new(0, 0)
        }
        fn home_tz(&self) -> chrono_tz::Tz {
            chrono_tz::UTC
        }
    }
    struct Zero;
    impl Rng for Zero {
        fn fill(&self, buf: &mut [u8]) {
            buf.fill(0);
        }
    }

    fn registry() -> AdapterRegistry {
        AdapterRegistry::with_builtins(Arc::new(Fixed), Arc::new(Zero))
    }

    #[test]
    fn builtins_register_the_features_this_build_enables() {
        let registry = registry();
        let kinds = registry.available_kinds();
        #[cfg(feature = "markdown")]
        assert!(kinds.contains(&SourceKindTag::MarkdownVault));
        #[cfg(feature = "journal")]
        assert!(kinds.contains(&SourceKindTag::Journal));
        #[cfg(feature = "structlog")]
        assert!(kinds.contains(&SourceKindTag::StructuredLog));
        // Networked adapters arrive with M2 and are not in this build.
        assert!(!kinds.contains(&SourceKindTag::NostrFeed));
    }

    /// The state this registry exists to make visible: configured, but not
    /// available in this build.
    #[test]
    fn an_unavailable_kind_is_absent_rather_than_silently_skipped() {
        let registry = registry();
        assert!(registry.get(SourceKindTag::Rss).is_none());
    }

    #[cfg(feature = "markdown")]
    #[test]
    fn registering_the_same_kind_twice_replaces_rather_than_duplicates() {
        let mut registry = registry();
        let before = registry.available_kinds().len();
        registry.register(Box::new(crate::markdown::MarkdownAdapter::new(
            Arc::new(Fixed),
            Arc::new(Zero),
        )));
        assert_eq!(registry.available_kinds().len(), before);
    }

    /// No local adapter may claim it stays offline while reaching the network,
    /// and none of the three in this build reaches it at all.
    #[cfg(all(feature = "markdown", feature = "journal", feature = "structlog"))]
    #[test]
    fn every_builtin_in_this_build_is_offline() {
        let registry = registry();
        for kind in registry.available_kinds() {
            let described = registry.describe(kind).expect("registered");
            assert!(!described.touches_network, "{kind:?} claims network access");
        }
    }
}
