//! Configuration.
//!
//! Every privacy-relevant default is the restrictive one. A user who never opens
//! this file runs fully local, publishes nothing, and anchors locally.
//!
//! M0's surface is deliberately small: the daemon settings (job queue,
//! scheduling, relays, quests) arrive with the milestones that need them rather
//! than sitting here unused (CLAUDE.md §9).

use ghostr_nostr::client::PublishScope;
use std::path::{Path, PathBuf};

use chrono_tz::Tz;
use serde::{Deserialize, Serialize};

/// The config filename inside the data directory.
pub const CONFIG_FILENAME: &str = "config.toml";

/// The M0 configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    /// The zone cutoffs are decided in.
    ///
    /// The user's *home* zone, not the ambient one, so travelling does not
    /// silently reshape their days (SPEC Q11).
    pub home_tz: String,
    /// Local time of day the cutoff falls at, in minutes past midnight.
    pub cutoff_minute_of_day: u16,
    /// OpenTimestamps calendars to submit chain tips to.
    pub calendars: Vec<String>,
    /// Whether anchoring is attempted automatically after sealing.
    ///
    /// **False by default.** Anchoring is the only command that touches the
    /// network, and it should be a thing the user asks for rather than a thing
    /// that happens because they wrote a note.
    pub auto_anchor: bool,
    /// Whether any content may leave the device for a model at all.
    ///
    /// **False by default**, and the master switch: with it off, no
    /// `egress_allow` entry does anything. Two settings rather than one because
    /// "turn it all off" should not mean editing a list.
    pub egress_enabled: bool,
    /// Which `provider:task` pairs may egress, e.g. `anthropic:summarization`.
    ///
    /// Per task, not per provider. Enabling a provider for conversation must not
    /// silently enable it for bulk extraction over the whole corpus (SPEC §11.2).
    pub egress_allow: Vec<String>,
    /// Relays to publish to and restore from.
    ///
    /// **Empty by default.** A vault with no relays is a vault that has never
    /// spoken to the network, which is the state a new one should be in.
    pub relays: Vec<String>,
    /// Whether `ghostr serve` seals days that are over, by itself.
    ///
    /// **False by default**, because sealing is irreversible: a sealed footage
    /// is immutable and a correction becomes an amendment in a later day (I2).
    /// Turning that on for someone who did not ask is not a convenience, it is a
    /// decision about their history made on their behalf.
    ///
    /// With it on, `serve` becomes the thing that keeps the chain current —
    /// which is why it lives there rather than in a cron job: `serve` already
    /// holds an unlocked vault, so nothing has to put a passphrase in an
    /// environment variable or a file to make this work.
    pub auto_seal: bool,
    /// How long after a day's cutoff before `auto_seal` closes it.
    ///
    /// People write the day up afterwards — on the train, the next morning, on
    /// Sunday for the whole week. A footage sealed before those notes arrive
    /// strands them as amendments to a day that is already closed, so the
    /// default waits until the following morning rather than sealing at
    /// midnight.
    pub seal_grace_hours: u32,
    /// How far back `auto_seal` will fill in on one run.
    ///
    /// A vault nobody has opened for a year should not seal three hundred empty
    /// days on the next launch. It seals the recent ones and leaves the rest to
    /// a deliberate `ghostr memoria --date`, because a month of silence is a
    /// fact about that month and backfilling it silently would hide it.
    pub seal_backfill_days: u32,
    /// Which publish scopes are enabled, by name.
    ///
    /// **Empty by default**, and per scope rather than a single boolean:
    /// enabling encrypted backup must not silently enable the ghost to post.
    /// Names match [`PublishScope`] in
    /// snake case — `backup`, `manifest`, `anchor_receipts`, `fidelity`,
    /// `ghost_notes`.
    ///
    /// `anchor_receipts` is absent from the default on purpose: a receipt on a
    /// relay proves a chain is alive, which is a fact about the person behind it
    /// (SPEC Q5).
    pub publish_scopes: Vec<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            home_tz: "UTC".to_owned(),
            // 23:59 local.
            cutoff_minute_of_day: 23 * 60 + 59,
            calendars: ghostr_anchor::default_calendars()
                .into_iter()
                .map(|c| c.url)
                .collect(),
            auto_anchor: false,
            egress_enabled: false,
            egress_allow: Vec::new(),
            auto_seal: false,
            // 06:00 the next morning, for a 23:59 cutoff.
            seal_grace_hours: 6,
            seal_backfill_days: 30,
            relays: Vec::new(),
            publish_scopes: Vec::new(),
        }
    }
}

impl Config {
    /// Loads config from a directory, falling back to defaults.
    ///
    /// A missing file is not an error: the defaults are the intended
    /// configuration and most users will never write one.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Config`](crate::Error::Config) if the file exists but
    /// does not parse — a malformed config is a real problem and silently
    /// ignoring it would run the user under settings they did not choose.
    pub fn load(dir: &Path) -> crate::Result<Self> {
        let path = dir.join(CONFIG_FILENAME);
        if !path.is_file() {
            return Ok(Self::default());
        }
        let text = std::fs::read_to_string(&path).map_err(|_| crate::Error::Config {
            detail: "config is unreadable".to_owned(),
        })?;
        // M0 config is a handful of scalars, so it is parsed with a two-line
        // key=value reader rather than pulling a TOML dependency for it.
        let mut config = Self::default();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let Some((key, value)) = line.split_once('=') else {
                return Err(crate::Error::Config {
                    detail: format!("malformed line in {}", path.display()),
                });
            };
            let value = value.trim().trim_matches('"');
            match key.trim() {
                "home_tz" => config.home_tz = value.to_owned(),
                "cutoff_minute_of_day" => {
                    config.cutoff_minute_of_day =
                        value.parse().map_err(|_| crate::Error::Config {
                            detail: "cutoff_minute_of_day is not a number".to_owned(),
                        })?;
                }
                "auto_anchor" => config.auto_anchor = value == "true",
                "egress_enabled" => config.egress_enabled = value == "true",
                "egress_allow" => config.egress_allow = string_list(value),
                // Read by `sync` and `restore`, and until now unsettable: the
                // field existed, the CLI told users to put `relays = [...]` in
                // this file, and this parser rejected the key as unknown. So
                // the list was always empty and both commands always refused.
                "relays" => config.relays = string_list(value),
                "calendars" => config.calendars = string_list(value),
                other => {
                    return Err(crate::Error::Config {
                        detail: format!("unknown config key `{other}`"),
                    });
                }
            }
        }
        Ok(config)
    }

    /// The home timezone, parsed.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Config`](crate::Error::Config) if it is not an IANA zone.
    pub fn tz(&self) -> crate::Result<Tz> {
        self.home_tz.parse().map_err(|_| crate::Error::Config {
            detail: format!("`{}` is not an IANA timezone", self.home_tz),
        })
    }

    /// The default data directory: `$XDG_DATA_HOME/ghostr` or `~/.ghostr`.
    #[must_use]
    pub fn default_dir() -> PathBuf {
        std::env::var_os("GHOSTR_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("XDG_DATA_HOME").map(|d| PathBuf::from(d).join("ghostr")))
            .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".ghostr")))
            .unwrap_or_else(|| PathBuf::from(".ghostr"))
    }
}

impl Config {
    /// The publish scopes this vault has enabled.
    ///
    /// An unknown name is ignored rather than refused. A config naming a scope
    /// this build does not have is a config from a newer build, and the safe
    /// reading of "backup, something_new" is to enable backup — not to refuse
    /// to start, and not to enable everything.
    #[must_use]
    pub fn enabled_scopes(&self) -> std::collections::HashSet<PublishScope> {
        self.publish_scopes
            .iter()
            .filter_map(|name| match name.as_str() {
                "backup" => Some(PublishScope::Backup),
                "manifest" => Some(PublishScope::Manifest),
                "anchor_receipts" => Some(PublishScope::AnchorReceipts),
                "fidelity" => Some(PublishScope::Fidelity),
                "ghost_notes" => Some(PublishScope::GhostNotes),
                _ => None,
            })
            .collect()
    }
}

/// Parses a list value, in TOML array form or bare comma-separated form.
///
/// Both, because the file is called `config.toml` and the CLI's own error
/// messages print TOML arrays, while this hand-rolled parser only ever
/// understood the bare form. A vault written either way keeps working, and a
/// user who writes what the error message told them to no longer gets
/// `unknown config key`.
fn string_list(value: &str) -> Vec<String> {
    value
        .trim()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .split(',')
        .map(|item| item.trim().trim_matches('"').trim().to_owned())
        .filter(|item| !item.is_empty())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_offline_and_restrictive() {
        let c = Config::default();
        assert!(!c.auto_anchor, "the network must never be touched unasked");
        assert!(!c.calendars.is_empty());
    }

    #[test]
    fn a_missing_config_is_not_an_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        assert_eq!(Config::load(dir.path()).expect("load"), Config::default());
    }

    #[test]
    fn a_malformed_config_is_refused_rather_than_ignored() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join(CONFIG_FILENAME), "this is not config\n").expect("write");
        assert!(Config::load(dir.path()).is_err());
    }

    /// The key `sync` and `restore` need, and the one the CLI's own error
    /// message tells the user to write. It was rejected as unknown.
    #[test]
    fn relays_can_actually_be_configured() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            dir.path().join(CONFIG_FILENAME),
            "relays = [\"wss://one.example\", \"wss://two.example\"]\n",
        )
        .expect("write");
        let config = Config::load(dir.path()).expect("load");
        assert_eq!(
            config.relays,
            vec![
                "wss://one.example".to_owned(),
                "wss://two.example".to_owned()
            ]
        );
    }

    /// A list written the bare way an older vault used keeps working.
    #[test]
    fn a_list_parses_in_either_form() {
        assert_eq!(
            string_list("[\"wss://a\", \"wss://b\"]"),
            vec!["wss://a".to_owned(), "wss://b".to_owned()]
        );
        assert_eq!(
            string_list("wss://a, wss://b"),
            vec!["wss://a".to_owned(), "wss://b".to_owned()]
        );
        assert_eq!(string_list("[]"), Vec::<String>::new());
        assert_eq!(string_list(""), Vec::<String>::new());
        assert_eq!(string_list("  one  "), vec!["one".to_owned()]);
    }

    #[test]
    fn an_unknown_key_is_refused() {
        // Silently ignoring it would run the user under settings they thought
        // they had changed.
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join(CONFIG_FILENAME), "auto_anhcor = true\n").expect("write");
        assert!(Config::load(dir.path()).is_err());
    }

    #[test]
    fn values_round_trip() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            dir.path().join(CONFIG_FILENAME),
            "# a comment\nhome_tz = \"Asia/Bangkok\"\nauto_anchor = true\n",
        )
        .expect("write");
        let c = Config::load(dir.path()).expect("load");
        assert!(c.auto_anchor);
        assert_eq!(c.tz().expect("tz").name(), "Asia/Bangkok");
    }
}
