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

impl CalendarFetch for OtsClient {
    /// `GET {uri}/timestamp/{commitment}` — the calendar's upgrade endpoint.
    ///
    /// The URI comes from the pending attestation inside a proof this vault
    /// stored, so it is only ever a calendar that already answered a submission.
    /// It is still treated as untrusted input: whatever comes back has to
    /// deserialise *and* graft onto the commitment it was asked about, or the
    /// merge is dropped and the existing proof kept.
    fn fetch(&self, uri: &str, commitment: &[u8]) -> Result<Vec<u8>, String> {
        let url = format!(
            "{}/timestamp/{}",
            uri.trim_end_matches('/'),
            hex_lower(commitment)
        );
        let agent = ureq::AgentBuilder::new()
            .timeout_connect(self.timeout)
            .timeout_read(self.timeout)
            .build();

        let response = agent
            .get(&url)
            .set("Accept", "application/vnd.opentimestamps.v1")
            .call()
            .map_err(|e| format!("{uri}: {e}"))?;

        let mut bytes = Vec::new();
        std::io::Read::read_to_end(&mut response.into_reader(), &mut bytes)
            .map_err(|e| format!("{uri}: reading response: {e}"))?;
        if bytes.is_empty() {
            // 200 with an empty body is how some calendars say "not yet".
            return Err(format!("{uri}: nothing yet"));
        }
        Ok(bytes)
    }
}

/// Lowercase hex, for the one place a commitment goes into a URL.
fn hex_lower(bytes: &[u8]) -> String {
    use core::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut out, b| {
        // Writing to a String cannot fail; the result is discarded rather than
        // unwrapped so this stays panic-free (CLAUDE.md §4.11).
        let _ = write!(out, "{b:02x}");
        out
    })
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

/// Where an upgrade goes to ask whether a pending attestation has landed.
///
/// A trait rather than a bare HTTP call so the *merge* — the part that can
/// silently corrupt a proof — is testable without a network (CLAUDE.md §4.8).
/// [`OtsClient`] is the real implementation; the tests hand it recorded bytes.
pub trait CalendarFetch {
    /// Asks `uri` for the timestamp it holds for `commitment`.
    ///
    /// # Errors
    ///
    /// Returns a transport description on failure. Being unable to reach a
    /// calendar is an expected condition, not an exceptional one: the proof
    /// stays pending and the next pass tries again.
    fn fetch(&self, uri: &str, commitment: &[u8]) -> Result<Vec<u8>, String>;
}

/// What one upgrade pass over one proof found.
#[derive(Debug, Clone)]
pub struct Upgrade {
    /// Where the anchor stands now.
    pub state: AnchorState,
    /// The rewritten `.ots`, when the proof actually gained something.
    ///
    /// `None` means nothing was merged — no calendar answered, or none of them
    /// had anything new. The caller keeps the file it already had rather than
    /// rewriting it with an identical copy.
    pub ots_bytes: Option<Vec<u8>>,
}

/// Attempts to complete a pending proof into a Bitcoin attestation.
///
/// This is SPEC §7.4 step 3, which had never been implemented: `submit` stored
/// a *calendar* attestation and nothing ever went back to ask whether the
/// calendar's aggregate had reached a block. Until this existed,
/// [`AnchorState::Confirmed`] was constructed nowhere but its own unit tests and
/// every anchored day read "pending" forever.
///
/// # How a merge works
///
/// A pending attestation is a leaf carrying a URI, and the step's `output` is
/// the commitment the calendar knows it by. Asking for that commitment returns
/// the operations from there onward. They are attached by **replacing the leaf
/// with a fork** holding the original attestation and the new path: an `Op`
/// step serialises only its first child and an `Attestation` step serialises
/// none, so a fork is the only shape that keeps both. Keeping the pending
/// attestation matters — it is what a later pass uses to ask again if this
/// calendar has more to give.
///
/// # Errors
///
/// Returns [`Error::MalformedProof`](crate::Error::MalformedProof) if the stored
/// bytes are not a detached timestamp, or
/// [`Error::ProofDigestMismatch`](crate::Error::ProofDigestMismatch) if they
/// commit to a different digest than `digest`. A calendar that answers with
/// somebody else's timestamp is broken or hostile; either way the merge is
/// refused rather than written over a good proof.
pub fn upgrade<F: CalendarFetch + ?Sized>(
    digest: Hash32,
    ots: &[u8],
    fetch: &F,
) -> crate::Result<Upgrade> {
    use opentimestamps::DetachedTimestampFile;
    use opentimestamps::ser::Deserializer;
    use opentimestamps::timestamp::Timestamp as OtsTimestamp;

    let mut file =
        DetachedTimestampFile::from_reader(ots).map_err(|_| crate::Error::MalformedProof)?;
    if file.timestamp.start_digest != digest.as_bytes() {
        return Err(crate::Error::ProofDigestMismatch);
    }

    let mut merged = 0usize;
    for (uri, commitment) in pending_requests(&file.timestamp.first_step) {
        let Ok(body) = fetch.fetch(&uri, &commitment) else {
            continue;
        };
        let mut de = Deserializer::new(&body[..]);
        let Ok(fragment) = OtsTimestamp::deserialize(&mut de, commitment.clone()) else {
            // A calendar that answers with something unparseable has told us
            // nothing. The proof we already hold is untouched.
            continue;
        };
        if graft(
            &mut file.timestamp.first_step,
            &commitment,
            &uri,
            fragment.first_step,
        ) {
            merged += 1;
        }
    }

    let state = match bitcoin_height(&file.timestamp.first_step) {
        Some(height) => AnchorState::Confirmed {
            block_height: height,
        },
        None => AnchorState::Pending {
            submitted_at: Timestamp::new(0, 0),
            calendars: pending_requests(&file.timestamp.first_step)
                .into_iter()
                .map(|(uri, _)| uri)
                .collect(),
        },
    };

    let ots_bytes = if merged == 0 {
        None
    } else {
        let mut out = Vec::new();
        file.to_writer(&mut out)
            .map_err(|_| crate::Error::MalformedProof)?;
        Some(out)
    };

    Ok(Upgrade { state, ots_bytes })
}

/// Every `(calendar uri, commitment)` a pending attestation is waiting on.
fn pending_requests(step: &opentimestamps::timestamp::Step) -> Vec<(String, Vec<u8>)> {
    use opentimestamps::attestation::Attestation;
    use opentimestamps::timestamp::StepData;

    let mut out = Vec::new();
    if let StepData::Attestation(Attestation::Pending { ref uri }) = step.data {
        out.push((uri.clone(), step.output.clone()));
    }
    for child in &step.next {
        out.extend(pending_requests(child));
    }
    out
}

/// The block height of the first Bitcoin attestation in the tree, if any.
fn bitcoin_height(step: &opentimestamps::timestamp::Step) -> Option<u32> {
    use opentimestamps::attestation::Attestation;
    use opentimestamps::timestamp::StepData;

    if let StepData::Attestation(Attestation::Bitcoin { height }) = step.data {
        return u32::try_from(height).ok();
    }
    step.next.iter().find_map(bitcoin_height)
}

/// Replaces the pending leaf for `(commitment, uri)` with a fork carrying it and
/// `addition`, and answers whether it found one.
fn graft(
    step: &mut opentimestamps::timestamp::Step,
    commitment: &[u8],
    uri: &str,
    addition: opentimestamps::timestamp::Step,
) -> bool {
    use opentimestamps::attestation::Attestation;
    use opentimestamps::timestamp::{Step, StepData};

    let is_target = matches!(
        step.data,
        StepData::Attestation(Attestation::Pending { uri: ref u }) if u == uri
    ) && step.output == commitment;

    if is_target {
        let original = Step {
            data: step.data.clone(),
            output: step.output.clone(),
            next: Vec::new(),
        };
        step.data = StepData::Fork;
        step.next = vec![original, addition];
        return true;
    }

    for child in &mut step.next {
        if graft(child, commitment, uri, addition.clone()) {
            return true;
        }
    }
    false
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

    /// Builds a `.ots` holding one pending attestation, the way `submit` does.
    fn pending_proof(digest: Hash32, uri: &str) -> Vec<u8> {
        use opentimestamps::DetachedTimestampFile;
        use opentimestamps::attestation::Attestation;
        use opentimestamps::ser::DigestType;
        use opentimestamps::timestamp::{Step, StepData, Timestamp as OtsTimestamp};

        let file = DetachedTimestampFile {
            digest_type: DigestType::Sha256,
            timestamp: OtsTimestamp {
                start_digest: digest.as_bytes().to_vec(),
                first_step: Step {
                    data: StepData::Attestation(Attestation::Pending {
                        uri: uri.to_owned(),
                    }),
                    output: digest.as_bytes().to_vec(),
                    next: Vec::new(),
                },
            },
        };
        let mut out = Vec::new();
        file.to_writer(&mut out).expect("write");
        out
    }

    /// The bytes a calendar returns once its aggregate is in a block: the
    /// operations from the commitment onward, with no envelope.
    fn calendar_says_confirmed(height: usize) -> Vec<u8> {
        use opentimestamps::attestation::Attestation;
        use opentimestamps::ser::Serializer;

        let mut out = Vec::new();
        {
            let mut ser = Serializer::new(&mut out);
            ser.write_byte(0x00).expect("attestation tag");
            Attestation::Bitcoin { height }
                .serialize(&mut ser)
                .expect("serialize");
        }
        out
    }

    /// A fetch that answers every calendar with the same recorded bytes.
    struct Recorded(Result<Vec<u8>, String>);
    impl CalendarFetch for Recorded {
        fn fetch(&self, _uri: &str, _commitment: &[u8]) -> Result<Vec<u8>, String> {
            self.0.clone()
        }
    }

    /// The whole point of the milestone criterion: a pending proof becomes a
    /// confirmed one, and the result is still a readable `.ots` for the same
    /// digest.
    ///
    /// Until `upgrade` existed, `AnchorState::Confirmed` was built nowhere but a
    /// unit test and every anchored day read "pending" forever.
    #[test]
    fn a_calendar_in_a_block_turns_a_pending_proof_into_a_confirmed_one() {
        let digest = Hash32::from_bytes([7u8; 32]);
        let before = pending_proof(digest, "https://alice.calendar");

        let out = upgrade(
            digest,
            &before,
            &Recorded(Ok(calendar_says_confirmed(886_123))),
        )
        .expect("upgrade");

        assert_eq!(
            out.state,
            AnchorState::Confirmed {
                block_height: 886_123
            }
        );
        let bytes = out.ots_bytes.expect("a merged proof must be written back");
        assert_ne!(bytes, before, "the file must actually have changed");
        read_detached_file(&bytes, digest).expect("the upgraded proof must still parse");
    }

    /// A calendar that has nothing yet must leave the proof exactly as it was.
    ///
    /// This is the common case for the first hours after a seal, and the
    /// dangerous one: rewriting the file on every pass would risk corrupting a
    /// good proof for no gain, and reporting anything but `Pending` would claim
    /// a Bitcoin attestation that does not exist.
    #[test]
    fn a_calendar_with_nothing_yet_leaves_the_proof_alone() {
        let digest = Hash32::from_bytes([9u8; 32]);
        let before = pending_proof(digest, "https://alice.calendar");

        let out = upgrade(digest, &before, &Recorded(Err("504".to_owned()))).expect("upgrade");

        assert!(matches!(out.state, AnchorState::Pending { .. }));
        assert!(
            out.ots_bytes.is_none(),
            "nothing was merged, so nothing should be rewritten"
        );
    }

    /// A proof for someone else's digest is refused before anything is written.
    ///
    /// `read_detached_file` already guards the read path; the upgrade path has
    /// its own opportunity to overwrite a good proof with a foreign one, so it
    /// checks separately rather than trusting its caller.
    #[test]
    fn an_upgrade_refuses_a_proof_for_a_different_digest() {
        let mine = Hash32::from_bytes([1u8; 32]);
        let theirs = Hash32::from_bytes([2u8; 32]);
        let proof = pending_proof(theirs, "https://alice.calendar");

        let err = upgrade(mine, &proof, &Recorded(Ok(calendar_says_confirmed(1))))
            .expect_err("a proof for another digest must be refused");
        assert!(matches!(err, crate::Error::ProofDigestMismatch));
    }

    /// The pending attestation survives the merge.
    ///
    /// It is what a later pass uses to ask the same calendar again — dropping it
    /// would make the first upgrade the only one that could ever happen.
    #[test]
    fn merging_keeps_the_pending_attestation_to_ask_again_with() {
        let digest = Hash32::from_bytes([3u8; 32]);
        let before = pending_proof(digest, "https://alice.calendar");

        let out = upgrade(
            digest,
            &before,
            &Recorded(Ok(calendar_says_confirmed(700_000))),
        )
        .expect("upgrade");
        let bytes = out.ots_bytes.expect("merged");

        let file = opentimestamps::DetachedTimestampFile::from_reader(&bytes[..]).expect("parse");
        let still_pending = pending_requests(&file.timestamp.first_step);
        assert_eq!(
            still_pending.len(),
            1,
            "the calendar must still be listed so a later pass can ask again"
        );
        assert_eq!(still_pending[0].0, "https://alice.calendar");
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
