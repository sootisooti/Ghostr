//! The local API.
//!
//! JSON-RPC over a Unix domain socket, or a named pipe on Windows. The CLI, a
//! future desktop shell, and user scripts all speak it.
//!
//! **Never a TCP listener by default.** A loopback TCP port is reachable by every
//! other process and container on the machine, and this one answers questions
//! about the contents of someone's memory.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

/// Where the API listens.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "transport")]
#[non_exhaustive]
pub enum ApiTransport {
    /// A Unix domain socket, mode 0600.
    ///
    /// Filesystem permissions do the access control, which is what makes this
    /// the default.
    UnixSocket {
        /// Socket path.
        path: std::path::PathBuf,
    },
    /// A Windows named pipe with an owner-only DACL.
    NamedPipe {
        /// Pipe name.
        name: String,
    },
}

/// Serves the local API.
#[async_trait]
pub trait LocalApi: Send + Sync {
    /// Starts listening.
    ///
    /// # Errors
    ///
    /// Returns an error if the socket cannot be created with the required
    /// permissions. Failing is correct: falling back to a laxer mode would
    /// quietly widen access to the corpus.
    async fn serve(&self, transport: ApiTransport) -> crate::Result<()>;

    /// Stops listening.
    async fn shutdown(&self);
}

/// A request over the local API.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "method", content = "params")]
#[non_exhaustive]
pub enum Request {
    /// Engine and chain status.
    Status,
    /// Unlock the keystore.
    ///
    /// The passphrase crosses the socket, which is why the socket is 0600 and
    /// never TCP.
    Unlock {
        /// The passphrase.
        passphrase: String,
    },
    /// Lock the keystore.
    Lock,
    /// Add a journal entry.
    Note {
        /// The text.
        text: String,
    },
    /// Seal any pending windows.
    Seal,
    /// Fetch today's open quests.
    Quests,
    /// Answer a quest.
    Answer {
        /// Which quest.
        quest_id: ghostr_core::ids::QuestId,
        /// The verdict.
        verdict: ghostr_core::quest::Verdict,
    },
    /// Fetch the fidelity score.
    Fidelity,
    /// Verify the chain.
    Verify {
        /// Start sequence, or `None` for genesis.
        from_seq: Option<u64>,
    },
    /// Read the egress log.
    EgressLog {
        /// How far back, in days.
        days: u32,
    },
}

/// Engine and chain status.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Status {
    /// Whether the keystore is locked.
    pub locked: bool,
    /// This device's id.
    pub device_id: String,
    /// Whether this device may seal.
    pub is_sealer: bool,
    /// The chain tip.
    pub tip_seq: Option<u64>,
    /// Windows awaiting a seal.
    pub pending_seals: u32,
    /// Sequences awaiting a Bitcoin attestation.
    pub pending_anchors: u32,
    /// The model in use, and whether it is local.
    pub model: String,
    /// Whether any remote provider is configured at all.
    ///
    /// Surfaced in `gst status` because "can this thing talk to the internet"
    /// should be answerable at a glance, not by reading a config file.
    pub remote_model_configured: bool,
}
