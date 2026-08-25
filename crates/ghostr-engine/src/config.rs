//! Configuration.
//!
//! Every privacy-relevant default is the restrictive one. A user who never opens
//! this file runs fully local, publishes nothing, and anchors locally.
//!
//! M0's surface is deliberately small: the daemon settings (job queue,
//! scheduling, relays, quests) arrive with the milestones that need them rather
//! than sitting here unused (CLAUDE.md §9).

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
                "calendars" => {
                    config.calendars = value
                        .split(',')
                        .map(|s| s.trim().to_owned())
                        .filter(|s| !s.is_empty())
                        .collect();
                }
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
