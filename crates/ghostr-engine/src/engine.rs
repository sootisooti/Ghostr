//! The engine: everything wired together.

use std::sync::Arc;

use ghostr_anchor::{Anchorer, CommitmentChain};
use ghostr_core::time::{Clock, Rng};
use ghostr_crypto::{Keystore, Signer};
use ghostr_ingest::AdapterRegistry;
use ghostr_llm::{Embedder, LanguageModel};
use ghostr_memoria::MemoriaPipeline;
use ghostr_persona::{PersonaBuilder, Retriever};
use ghostr_quests::{QuestGenerator, Scorer, VerdictIntake};
use ghostr_store::{
    BlobStore, EntityStore, FootageStore, MemoryStore, PersonaStore, QuestStore, VectorIndex,
};

use crate::config::Config;

/// Everything wired together.
///
/// Constructed once at startup. Every field is a trait object, which is what
/// lets the whole thing run against fakes in an integration test with no
/// database, no model, and no network.
pub struct Engine {
    config: Config,
    clock: Arc<dyn Clock>,
    rng: Arc<dyn Rng>,
    keystore: Arc<dyn Keystore>,
    signer: Arc<dyn Signer>,
    memories: Arc<dyn MemoryStore>,
    footage: Arc<dyn FootageStore>,
    quests_store: Arc<dyn QuestStore>,
    persona_store: Arc<dyn PersonaStore>,
    entities: Arc<dyn EntityStore>,
    blobs: Arc<dyn BlobStore>,
    vectors: Arc<dyn VectorIndex>,
    model: Arc<dyn LanguageModel>,
    embedder: Arc<dyn Embedder>,
    adapters: AdapterRegistry,
    memoria: Arc<dyn MemoriaPipeline>,
    persona: Arc<dyn PersonaBuilder>,
    retriever: Arc<dyn Retriever>,
    generator: Arc<dyn QuestGenerator>,
    intake: Arc<dyn VerdictIntake>,
    scorer: Arc<dyn Scorer>,
    chain: Arc<dyn CommitmentChain>,
    anchorer: Arc<dyn Anchorer>,
}

impl core::fmt::Debug for Engine {
    /// Prints which implementations are wired, never their state.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        todo!("print the model descriptor, device id and lock state")
    }
}

impl Engine {
    /// Builds an engine from configuration.
    ///
    /// The real [`Clock`] and [`Rng`] are constructed here and nowhere else.
    /// `clippy.toml` bans the underlying constructors workspace-wide, so this
    /// function carries the single documented
    /// `#[allow(clippy::disallowed_methods)]` and every exception in the tree is
    /// one grep away (ARCHITECTURE §4.7).
    ///
    /// # Errors
    ///
    /// Returns [`Error::Config`](crate::Error::Config) if configuration is
    /// unusable, or an underlying error if a component fails to construct.
    pub fn build(config: Config) -> crate::Result<Self> {
        todo!("construct the real clock, rng, store, model and pipelines")
    }

    /// Unlocks the keystore.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Crypto`](crate::Error::Crypto) with
    /// `BadPassphrase` if the passphrase is wrong.
    pub fn unlock(&self, passphrase: ghostr_crypto::secret::SecretString) -> crate::Result<()> {
        todo!("unlock the keystore and start the auto-lock timer")
    }

    /// Locks the keystore and zeroizes the keys.
    pub fn lock(&self) {
        todo!("lock the keystore")
    }

    /// Whether this device may seal (SPEC Q10).
    ///
    /// Checked before every seal. Two devices advancing one chain is the failure
    /// that produces a fork, and a forked chain is worthless.
    ///
    /// # Errors
    ///
    /// Returns an error if the manifest cannot be read.
    pub fn is_sealing_device(&self) -> crate::Result<bool> {
        todo!("compare the configured device id against the manifest's sealer")
    }

    /// Runs any seals that are due, oldest first.
    ///
    /// Called at startup as well as on the schedule, so a machine that slept
    /// through three cutoffs catches up rather than skipping them.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotSealer`](crate::Error::NotSealer) on a replica.
    pub async fn seal_pending(&self) -> crate::Result<Vec<u64>> {
        todo!("compute pending windows, compile, validate and seal each in order")
    }
}
