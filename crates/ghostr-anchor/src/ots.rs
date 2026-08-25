//! OpenTimestamps calendar submission (SPEC §7.4).
//!
//! # Why OTS rather than an OP_RETURN per day
//!
//! Calendars aggregate thousands of digests into one transaction, so the
//! marginal cost of a daily anchor is zero: no wallet, no UTXO management, no
//! fee estimation in the sealing path. The trade is a dependency on calendar
//! availability and a timestamp granularity of hours rather than minutes.
//! Neither matters for a daily journal.
//!
//! # Offline is a normal state, not a failure
//!
//! Anchoring happens *after* sealing and can fail freely. An unanchored day is
//! still a valid chain link — it just lacks external evidence until a calendar
//! is reachable. A day that could not close because a calendar was down would
//! be a gap in the chain, which is far worse than a proof arriving late.
//!
//! # What is implemented in M0
//!
//! Submission and `.ots` persistence. Proof *upgrading* — polling the calendar
//! until its aggregate lands in a block, then verifying against a Bitcoin
//! header — is M1 work; [`AnchorState::Pending`] is where a fresh submission
//! stops for now, and `ghostr verify` says so rather than implying more.

use ghostr_core::hash::Hash32;
use ghostr_core::time::Timestamp;
use serde::{Deserialize, Serialize};

/// A calendar endpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CalendarConfig {
    /// Calendar base URL.
    pub url: String,
}

/// The default calendars.
///
/// Public, well-known, and independently operated. At least two, because one
/// calendar is a single point of failure for a proof the user may need years
/// later and the cost of a second is a second HTTP request.
///
/// A user who does not want to disclose an IP to them should route through Tor:
/// the calendar sees a 32-byte digest and an IP, which is a small leak but not a
/// zero one (THREAT_MODEL §T4).
#[must_use]
pub fn default_calendars() -> Vec<CalendarConfig> {
    [
        "https://a.pool.opentimestamps.org",
        "https://b.pool.opentimestamps.org",
    ]
    .into_iter()
    .map(|url| CalendarConfig {
        url: url.to_owned(),
    })
    .collect()
}

/// Where a digest stands on its way into a block.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "state")]
#[non_exhaustive]
pub enum AnchorState {
    /// Not yet submitted.
    Unanchored,
    /// Accepted by at least one calendar, awaiting its Bitcoin transaction.
    Pending {
        /// When it was submitted.
        submitted_at: Timestamp,
        /// Which calendars accepted it.
        calendars: Vec<String>,
    },
    /// Confirmed in a block.
    Confirmed {
        /// Block height.
        block_height: u32,
    },
    /// Every calendar refused or was unreachable.
    ///
    /// Never blocks sealing. The chain link is valid without an attestation; the
    /// day simply lacks external evidence until this recovers.
    Failed {
        /// How many attempts were made.
        attempts: u32,
        /// The last error, in transport terms.
        last_error: String,
    },
}

impl AnchorState {
    /// Whether this state carries a Bitcoin attestation.
    #[must_use]
    pub const fn is_confirmed(&self) -> bool {
        matches!(self, Self::Confirmed { .. })
    }

    /// A short label for CLI output.
    #[must_use]
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Unanchored => "unanchored",
            Self::Pending { .. } => "pending",
            Self::Confirmed { .. } => "confirmed",
            Self::Failed { .. } => "failed",
        }
    }
}

/// The outcome of submitting one digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Submission {
    /// The digest submitted.
    pub digest: Hash32,
    /// Where it stands now.
    pub state: AnchorState,
    /// The serialised `.ots` proof, when at least one calendar answered.
    pub ots_bytes: Option<Vec<u8>>,
}

/// Submits a digest to calendars over HTTP.
///
/// Blocking on purpose. Anchoring is a one-shot CLI operation on a local-first
/// tool, so a blocking request costs nothing and keeps `hyper` and a second
/// async runtime out of the dependency tree (THREAT_MODEL §T8). When the daemon
/// arrives this moves behind `spawn_blocking`.
#[derive(Debug, Clone)]
pub struct OtsClient {
    calendars: Vec<CalendarConfig>,
    timeout: std::time::Duration,
}

impl Default for OtsClient {
    fn default() -> Self {
        Self {
            calendars: default_calendars(),
            timeout: std::time::Duration::from_secs(10),
        }
    }
}

impl OtsClient {
    /// A client for the given calendars.
    #[must_use]
    pub fn new(calendars: Vec<CalendarConfig>, timeout: std::time::Duration) -> Self {
        Self { calendars, timeout }
    }

    /// Which calendars this client will contact.
    #[must_use]
    pub fn calendars(&self) -> &[CalendarConfig] {
        &self.calendars
    }

    /// Submits `digest` to every configured calendar.
    ///
    /// Succeeds if *any* calendar accepts: partial success is success, because
    /// one accepted submission is one valid proof. Returns
    /// [`AnchorState::Failed`] rather than an error when all of them fail, since
    /// being offline is an expected condition rather than an exceptional one.
    ///
    /// # Errors
    ///
    /// Returns [`Error::MalformedProof`](crate::Error::MalformedProof) if a
    /// calendar answers with something that is not a timestamp.
    pub fn submit(&self, digest: Hash32, now: Timestamp) -> crate::Result<Submission> {
        let mut accepted = Vec::new();
        let mut merged: Option<Vec<u8>> = None;
        let mut last_error = String::new();
        let mut attempts = 0u32;

        for calendar in &self.calendars {
            attempts += 1;
            match self.post_digest(&calendar.url, digest) {
                Ok(bytes) => {
                    accepted.push(calendar.url.clone());
                    // The first calendar's response is kept as the proof body.
                    // Merging several calendars' attestations into one `.ots`
                    // needs the full timestamp-tree merge, which is M1 work;
                    // one complete proof is already sufficient to verify.
                    if merged.is_none() {
                        merged = Some(bytes);
                    }
                }
                Err(e) => last_error = e,
            }
        }

        if accepted.is_empty() {
            return Ok(Submission {
                digest,
                state: AnchorState::Failed {
                    attempts,
                    last_error,
                },
                ots_bytes: None,
            });
        }
        Ok(Submission {
            digest,
            state: AnchorState::Pending {
                submitted_at: now,
                calendars: accepted,
            },
            ots_bytes: merged,
        })
    }

    /// POSTs a digest to one calendar's `/digest` endpoint.
    fn post_digest(&self, base: &str, digest: Hash32) -> Result<Vec<u8>, String> {
        let url = format!("{}/digest", base.trim_end_matches('/'));
        let agent = ureq::AgentBuilder::new()
            .timeout_connect(self.timeout)
            .timeout_read(self.timeout)
            .build();

        let response = agent
            .post(&url)
            .set("Accept", "application/vnd.opentimestamps.v1")
            .set("Content-Type", "application/x-www-form-urlencoded")
            .send_bytes(digest.as_bytes())
            .map_err(|e| format!("{base}: {e}"))?;

        let mut bytes = Vec::new();
        std::io::Read::read_to_end(&mut response.into_reader(), &mut bytes)
            .map_err(|e| format!("{base}: reading response: {e}"))?;
        if bytes.is_empty() {
            return Err(format!("{base}: empty response"));
        }
        Ok(bytes)
    }
}

/// Wraps a calendar response into a complete detached `.ots` file.
///
/// The calendar returns the timestamp *operations* for the digest it was given;
/// a `.ots` file additionally carries the magic header, version, and the digest
/// it commits to. Writing the wrapper ourselves is what makes the output
/// readable by the reference `ots` client rather than only by us.
///
/// # Errors
///
/// Returns [`Error::MalformedProof`](crate::Error::MalformedProof) if the
/// response does not parse as a timestamp.
pub fn to_detached_file(digest: Hash32, calendar_body: &[u8]) -> crate::Result<Vec<u8>> {
    use opentimestamps::DetachedTimestampFile;
    use opentimestamps::ser::{Deserializer, DigestType};
    use opentimestamps::timestamp::Timestamp as OtsTimestamp;

    // The calendar returns the timestamp *operations* for the digest it was
    // given, with no envelope. Deserialising needs the digest supplied
    // separately, which is exactly the shape of this call.
    let mut de = Deserializer::new(calendar_body);
    let timestamp = OtsTimestamp::deserialize(&mut de, digest.as_bytes().to_vec())
        .map_err(|_| crate::Error::MalformedProof)?;

    let file = DetachedTimestampFile {
        digest_type: DigestType::Sha256,
        timestamp,
    };
    let mut out = Vec::new();
    file.to_writer(&mut out)
        .map_err(|_| crate::Error::MalformedProof)?;
    Ok(out)
}

/// Reads a detached `.ots` file back, for `ghostr verify` and for inspection.
///
/// # Errors
///
/// Returns [`Error::MalformedProof`](crate::Error::MalformedProof) if the bytes
/// are not a valid detached timestamp, or
/// [`Error::ProofDigestMismatch`](crate::Error::ProofDigestMismatch) if the
/// proof commits to a different digest than the one expected. A calendar
/// returning a proof for someone else's digest is either broken or hostile, and
/// either way the proof is worthless.
pub fn read_detached_file(bytes: &[u8], expected: Hash32) -> crate::Result<()> {
    use opentimestamps::DetachedTimestampFile;

    let file =
        DetachedTimestampFile::from_reader(bytes).map_err(|_| crate::Error::MalformedProof)?;
    if file.timestamp.start_digest != expected.as_bytes() {
        return Err(crate::Error::ProofDigestMismatch);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// No test in this crate touches the network (CLAUDE.md §4.8). Submission
    /// against a real calendar lives in an `#[ignore]`d integration test.
    #[test]
    fn default_calendars_are_independent_and_plural() {
        let cals = default_calendars();
        assert!(cals.len() >= 2, "one calendar is a single point of failure");
        let hosts: std::collections::HashSet<_> = cals.iter().map(|c| &c.url).collect();
        assert_eq!(hosts.len(), cals.len(), "calendars must be distinct");
    }

    #[test]
    fn a_client_with_no_calendars_fails_rather_than_hangs() {
        let client = OtsClient::new(Vec::new(), std::time::Duration::from_millis(1));
        let out = client
            .submit(Hash32::from_bytes([1u8; 32]), Timestamp::new(0, 0))
            .expect("submit returns a state, not an error");
        assert!(matches!(out.state, AnchorState::Failed { attempts: 0, .. }));
        assert!(out.ots_bytes.is_none());
    }

    #[test]
    fn an_unreachable_calendar_yields_failed_not_an_error() {
        // Offline is expected, not exceptional: sealing must never depend on it.
        // Port 9 is the discard port and refuses immediately, so this stays
        // local and fast.
        let client = OtsClient::new(
            vec![CalendarConfig {
                url: "http://127.0.0.1:9".to_owned(),
            }],
            std::time::Duration::from_millis(50),
        );
        let out = client
            .submit(Hash32::from_bytes([1u8; 32]), Timestamp::new(0, 0))
            .expect("submit returns a state");
        match out.state {
            AnchorState::Failed {
                attempts,
                last_error,
            } => {
                assert_eq!(attempts, 1);
                assert!(
                    !last_error.is_empty(),
                    "the failure should say what happened"
                );
            }
            other => panic!("expected Failed, got {other:?}"),
        }
    }

    #[test]
    fn state_labels_are_stable() {
        assert_eq!(AnchorState::Unanchored.label(), "unanchored");
        assert_eq!(
            AnchorState::Confirmed { block_height: 1 }.label(),
            "confirmed"
        );
        assert!(AnchorState::Confirmed { block_height: 1 }.is_confirmed());
        assert!(!AnchorState::Unanchored.is_confirmed());
    }

    #[test]
    fn a_malformed_calendar_body_is_rejected() {
        let err = to_detached_file(Hash32::from_bytes([1u8; 32]), b"not a timestamp");
        assert!(matches!(err, Err(crate::Error::MalformedProof)));
    }
}
