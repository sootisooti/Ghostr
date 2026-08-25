//! Adapter lookup.

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
        todo!("print the registered source kinds")
    }
}

impl AdapterRegistry {
    /// A registry with every adapter this build enables.
    #[must_use]
    pub fn with_builtins() -> Self {
        todo!("register each adapter behind its feature flag")
    }

    /// Adds an adapter.
    pub fn register(&mut self, adapter: Box<dyn IngestAdapter>) {
        todo!("push, rejecting a duplicate kind")
    }

    /// Looks up the adapter for a kind.
    #[must_use]
    pub fn get(&self, kind: SourceKindTag) -> Option<&dyn IngestAdapter> {
        todo!("find the adapter whose kind() matches")
    }

    /// Every source kind this build can ingest.
    ///
    /// Backs `gst source add --help`, so the list a user sees is the list that
    /// actually works.
    #[must_use]
    pub fn available_kinds(&self) -> Vec<SourceKindTag> {
        todo!("collect the registered kinds")
    }
}
