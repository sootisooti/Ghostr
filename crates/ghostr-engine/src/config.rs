//! Configuration.
//!
//! Every privacy-relevant default is the restrictive one. A user who never opens
//! this file runs fully local, publishes nothing, and anchors locally.

use std::path::PathBuf;

use chrono_tz::Tz;
use serde::{Deserialize, Serialize};

/// The whole configuration.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Config {
    /// Where the store and keystore live.
    pub data_dir: PathBuf,
    /// This device's identifier.
    pub device_id: String,
    /// Cutoff and timezone settings.
    pub cutoff: CutoffConfig,
    /// Model settings.
    pub models: ModelConfig,
    /// Anchoring settings.
    pub anchor: AnchorConfig,
    /// Relay settings.
    pub relays: RelayConfig,
    /// Quest settings.
    pub quests: QuestConfig,
    /// Auto-lock settings.
    pub security: SecurityConfig,
}

/// When a day ends.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CutoffConfig {
    /// Local time of day in minutes past midnight. Default 23:59.
    pub minute_of_day: u16,
    /// The home zone, which decides the boundary regardless of travel.
    pub home_tz: Tz,
    /// Grace period before sealing runs.
    pub grace_minutes: u16,
}

/// Which models to use.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelConfig {
    /// The local model. Always present; this is the default path.
    pub local: ghostr_llm::gate::LocalModelConfig,
    /// A remote model, if the user has opted into one.
    ///
    /// `None` by default, and a stock build has no provider feature compiled in
    /// anyway — so the default configuration cannot egress even if this were
    /// set.
    pub remote: Option<ghostr_llm::gate::RemoteModelConfig>,
    /// The local embedding model. There is no remote option (SPEC Q13).
    pub embedder: String,
}

/// Anchoring settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnchorConfig {
    /// Calendars to submit to.
    pub calendars: Vec<String>,
    /// Whether to publish anchor receipts to relays.
    ///
    /// **False by default.** The `.ots` file on disk is already a complete
    /// proof, so publishing adds availability rather than validity — and a daily
    /// stream of receipts broadcasts that this person is alive and journaling
    /// (SPEC Q5).
    pub publish_receipts: bool,
    /// Where block headers come from for verification.
    pub header_source: Option<String>,
}

/// Relay settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayConfig {
    /// Configured relays.
    pub urls: Vec<String>,
    /// Which publishing scopes are enabled. Empty by default.
    pub enabled_scopes: Vec<ghostr_nostr::client::PublishScope>,
    /// Wrap events in NIP-59 gift wrap.
    pub gift_wrap: bool,
    /// SOCKS5 proxy for relay and calendar traffic.
    pub proxy: Option<String>,
}

/// Quest settings.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct QuestConfig {
    /// Target quests per day.
    pub daily_count: u8,
    /// Local time to issue them, in minutes past midnight.
    pub issue_minute_of_day: u16,
    /// Holdout and decoy policy.
    pub holdout: ghostr_quests::generate::HoldoutPolicy,
    /// Convergence thresholds.
    ///
    /// Config rather than constants: the numbers are a starting hypothesis and
    /// the first cohort's data is the calibration study (SPEC Q9).
    pub convergence: ghostr_quests::score::ConvergenceThresholds,
}

/// Locking behaviour.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityConfig {
    /// Idle minutes before the keystore locks itself.
    ///
    /// Minutes, not hours. The daily loop runs unattended, and auto-lock is the
    /// only thing between an unlocked corpus and whoever sits down next
    /// (THREAT_MODEL §T6).
    pub auto_lock_minutes: u16,
    /// Require re-authentication before export, forget, or enabling egress.
    pub reauth_for_sensitive_ops: bool,
    /// Minimum passphrase entropy in bits.
    pub min_passphrase_bits: u16,
}

impl Config {
    /// Loads config, applying defaults for anything absent.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Config`](crate::Error::Config) if the file is malformed.
    pub fn load(path: &std::path::Path) -> crate::Result<Self> {
        todo!("read TOML and merge over defaults")
    }

    /// The default configuration: fully local, publishes nothing.
    #[must_use]
    pub fn defaults(data_dir: PathBuf, device_id: String) -> Self {
        todo!("build the restrictive default configuration")
    }
}
