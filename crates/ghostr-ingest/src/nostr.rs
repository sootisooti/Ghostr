//! The nostr feed adapter: somebody else's text, arriving over the network.
//!
//! This is the adapter the rest of this crate's documentation has been warning
//! about. Everything before it reads a file the user put on their own disk;
//! this one reads whatever a relay decides to hand back, and hands it to a
//! language model (THREAT_MODEL §T7).
//!
//! # Three gates, none of them a comment
//!
//! **Trust.** [`default_trust`] is
//! [`ThirdParty`](ghostr_core::sensitivity::TrustLevel::ThirdParty), always. It
//! does not consult the configured pubkey, and it must not: a per-source
//! promotion to first-party would make the security control a configuration
//! field, and configuration is exactly what an attacker who can edit a vault's
//! settings would reach for. Whether a user's *own* signed notes should be
//! promotable is SPEC §14 Q23, deliberately unresolved rather than quietly
//! decided here.
//!
//! **Kind.** A feed note becomes [`MemoryKind::Observation`], never
//! [`MemoryKind::Utterance`] — `Utterance` is documented as the voice corpus,
//! so using it here would put a stranger's sentences in the ghost's mouth
//! through a second door that the trust level does not cover.
//!
//! **Provenance.** A relay is not a source of truth about what it serves. Every
//! event is signature-checked *here*, after
//! [`RelayClient`] has already checked it, and any
//! event whose author or kind is not what the filter asked for is dropped and
//! counted. The transport promising to verify is not the same as this crate
//! knowing it did, and a relay that ignores a filter is a relay that decides
//! what enters the corpus.

use std::sync::Arc;

use ghostr_core::hash::{Tag, tagged_hash};
use ghostr_core::identity::PublicKey;
use ghostr_core::ids::{MemoryId, SourceId};
use ghostr_core::memory::{Memory, MemoryBody, MemoryKind, Provenance};
use ghostr_core::sensitivity::{Sensitivity, TrustLevel};
use ghostr_core::source::{Source, SourceKind, SourceKindTag, SyncCursor};
use ghostr_core::time::{Clock, Rng, Timestamp};
use ghostr_crypto::event::SignedEvent;
use ghostr_nostr::RelayClient;
use ghostr_nostr::client::Filter;

use crate::adapter::{IngestBatch, TimeBasis};

/// The source-kind tag this adapter registers under.
pub const KIND_TAG: &str = "nostr_feed";

/// Event kinds a feed may be configured to read.
///
/// Short text notes and long-form articles: the two NIP-01/NIP-23 kinds whose
/// `content` is prose a person wrote. Anything else — reactions, contact lists,
/// zap receipts, the Ghostr kinds themselves — is either not prose or not
/// somebody's writing, and a corpus built from reaction emoji is noise at best.
/// Configuring one is refused by [`validate_config`] rather than filtered at
/// pull, so a user finds out when they add the source.
pub const READABLE_KINDS: &[u16] = &[
    // NIP-01 short text note.
    1, // NIP-23 long-form content.
    30023,
];

/// How many notes one pull returns.
///
/// A prolific author's history is tens of thousands of notes. Bounded batches
/// are what make the import resumable rather than one request that has to
/// survive a laptop lid closing.
pub const BATCH_NOTES: usize = 256;

/// The trust level nostr feed content carries.
///
/// [`TrustLevel::ThirdParty`], unconditionally. Content from a relay is written
/// by someone else and read by a language model, which is the definition of the
/// prompt-injection surface (THREAT_MODEL §T7). Returning anything else here
/// would be a vulnerability, not a bug — see the crate documentation.
#[must_use]
pub const fn default_trust() -> TrustLevel {
    TrustLevel::ThirdParty
}

/// The sensitivity floor nostr feed content carries.
///
/// [`Sensitivity::Public`], because it is: the note was broadcast to relays by
/// its author before Ghostr ever saw it. Marking it `Private` would claim a
/// protection that does not exist and would push redacted egress decisions
/// around content that is already on the open internet.
#[must_use]
pub const fn default_sensitivity() -> Sensitivity {
    Sensitivity::Public
}

/// How a note's occurrence time is determined.
#[must_use]
pub const fn time_basis() -> TimeBasis {
    TimeBasis::Stated
}

/// Parses a 64-character lowercase-hex x-only pubkey.
///
/// # Errors
///
/// Returns [`Error::Unparseable`](crate::Error::Unparseable) if it is not 32
/// bytes of hex. The location names the field, never the value: a pubkey is not
/// secret, but keeping the "errors carry ids, not content" rule uniform is what
/// stops the one error that *does* carry content from looking normal.
pub fn parse_pubkey(hex_pubkey: &str, source: SourceId) -> crate::Result<PublicKey> {
    let bytes = hex::decode(hex_pubkey).map_err(|_| crate::Error::Unparseable {
        id: source,
        location: "pubkey".to_owned(),
    })?;
    let bytes: [u8; 32] = bytes.try_into().map_err(|_| crate::Error::Unparseable {
        id: source,
        location: "pubkey".to_owned(),
    })?;
    Ok(PublicKey::from_bytes(bytes))
}

/// Turns a verified event into a [`Memory`].
///
/// The event's content is stored verbatim. That is deliberate: rewriting
/// hostile text at ingest would leave the corpus unable to show what was
/// actually published, and the defence against injection is the prompt boundary
/// and the trust level, not a sanitiser that an attacker gets to probe.
///
/// # Errors
///
/// Returns [`Error::Unparseable`](crate::Error::Unparseable) if the note has no
/// content worth storing.
pub fn to_memory(
    event: &SignedEvent,
    source: SourceId,
    clock: &dyn Clock,
    rng: &dyn Rng,
) -> crate::Result<Memory> {
    let text = event.event.content.trim();
    if text.is_empty() {
        return Err(crate::Error::Unparseable {
            id: source,
            location: event.id.to_hex(),
        });
    }

    let now = clock.now();
    let mut random = [0u8; 10];
    rng.fill(&mut random);
    let mut salt = [0u8; 32];
    rng.fill(&mut salt);

    // Over the event id, which nostr already defines as the hash of the whole
    // canonical body. Two fetches of one note produce one memory, and an edited
    // note is a different note because it is a different id.
    let raw_hash = tagged_hash(Tag::MemoryLeaf, event.id.as_bytes());

    Ok(Memory {
        id: MemoryId::new(now.utc_millis().unsigned_abs(), random),
        source_id: source,
        occurred_at: Some(created_at_timestamp(event.event.created_at)),
        ingested_at: now,
        // Never `Utterance`. See the module documentation: that variant is the
        // voice corpus, and a feed note is something the user read.
        kind: MemoryKind::Observation,
        body: MemoryBody {
            text: text.to_owned(),
            structured: None,
            redactions: Vec::new(),
        },
        entities: Vec::new(),
        // Low, and deliberately below every first-party source. A day's recap
        // that ranks a stranger's note above what the user wrote themselves has
        // already lost the plot, whatever the trust level says downstream.
        salience: 0.2,
        sensitivity: default_sensitivity(),
        provenance: Provenance {
            source_id: source,
            external_id: Some(event.id.to_hex()),
            url: None,
            raw_hash,
        },
        salt,
        supersedes: None,
        embedding: None,
    })
}

/// A nostr `created_at`, in seconds, as a [`Timestamp`].
///
/// Saturating rather than wrapping: a relay can serve any `u64` it likes, and a
/// note claiming to be from the year 300 billion should land at the end of time
/// rather than wrap into the user's actual history.
fn created_at_timestamp(created_at: u64) -> Timestamp {
    let millis = i64::try_from(created_at)
        .unwrap_or(i64::MAX)
        .saturating_mul(1_000);
    Timestamp::new(millis, 0)
}

/// A nostr feed, as an [`IngestAdapter`](crate::IngestAdapter).
pub struct NostrFeedAdapter {
    client: Arc<dyn RelayClient>,
    clock: Arc<dyn Clock>,
    rng: Arc<dyn Rng>,
}

impl core::fmt::Debug for NostrFeedAdapter {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("NostrFeedAdapter")
    }
}

impl NostrFeedAdapter {
    /// Builds the adapter over a relay client, clock and entropy source.
    ///
    /// The client is injected rather than constructed: this crate has no
    /// business opening a socket, and a test that needed a real relay would be
    /// a test that never runs (CLAUDE.md §4.8).
    #[must_use]
    pub fn new(client: Arc<dyn RelayClient>, clock: Arc<dyn Clock>, rng: Arc<dyn Rng>) -> Self {
        Self { client, clock, rng }
    }
}

/// What a relay returned, after this crate has finished disbelieving it.
struct Screened {
    kept: Vec<SignedEvent>,
    /// Well-formed events the filter did not ask for.
    rejected: u32,
    /// Events from before the cursor: already seen, not suspicious.
    stale: u32,
}

/// Drops everything the relay returned that the filter did not ask for.
///
/// Three of these mean somebody may be trying something, and one does not, so
/// they are counted separately. A security signal that also fires on ordinary
/// relay slop is a signal nobody will look at twice.
///
/// **Rejected** — well-formed and wrong:
///
/// - **Signature.** [`RelayClient`] promises to verify before returning, and
///   this checks again anyway. A promise in a doc comment is not a property of
///   the running program, and the cost here is one signature check per note.
/// - **Author.** A relay can return events from anyone. An unfiltered author is
///   a stranger's note filed under someone the user chose to read.
/// - **Kind.** A relay can return kinds nobody asked for.
///
/// **Stale** — from before `since`. A relay that ignores the cursor is being
/// unhelpful rather than hostile, but the note is still dropped: re-admitting
/// one would undo a shred, and the day it reappeared would look like the author
/// had posted it again.
fn screen(
    events: Vec<SignedEvent>,
    author: PublicKey,
    kinds: &[u16],
    since: Option<u64>,
) -> Screened {
    let mut kept = Vec::with_capacity(events.len());
    let mut rejected = 0u32;
    let mut stale = 0u32;
    for event in events {
        if event.verify().is_err()
            || event.event.pubkey != author
            || !kinds.contains(&event.event.kind)
        {
            rejected = rejected.saturating_add(1);
        } else if since.is_some_and(|floor| event.event.created_at < floor) {
            stale = stale.saturating_add(1);
        } else {
            kept.push(event);
        }
    }
    Screened {
        kept,
        rejected,
        stale,
    }
}

/// Checks a feed's configuration without reaching a relay.
///
/// Separate from [`IngestAdapter::validate`](crate::IngestAdapter::validate)
/// because the composition root has to run these checks at `ghostr source add`,
/// where there may be no relay client yet and where a typo must fail
/// immediately rather than at the first sync.
///
/// # Errors
///
/// Returns [`Error::Unparseable`](crate::Error::Unparseable) naming the field
/// that is wrong — never its value.
pub fn validate_config(
    pubkey: &str,
    relays: &[String],
    kinds: &[u16],
    source: SourceId,
) -> crate::Result<()> {
    parse_pubkey(pubkey, source)?;
    if relays.is_empty() {
        return Err(crate::Error::Unparseable {
            id: source,
            location: "relays".to_owned(),
        });
    }
    // Refused here rather than filtered at pull. A feed configured to read
    // reactions would sync forever and produce nothing, which is the failure
    // mode this crate exists to avoid.
    if kinds.is_empty() || kinds.iter().any(|k| !READABLE_KINDS.contains(k)) {
        return Err(crate::Error::Unparseable {
            id: source,
            location: "kinds".to_owned(),
        });
    }
    Ok(())
}

#[async_trait::async_trait]
impl crate::adapter::IngestAdapter for NostrFeedAdapter {
    fn kind(&self) -> SourceKindTag {
        SourceKindTag::NostrFeed
    }

    async fn pull(&self, source: &Source, cursor: SyncCursor) -> crate::Result<IngestBatch> {
        let SourceKind::NostrFeed {
            pubkey,
            relays: _,
            kinds,
        } = &source.kind
        else {
            return Err(crate::Error::InvalidCursor { id: source.id });
        };
        let author = parse_pubkey(pubkey, source.id)?;

        let since = match cursor {
            SyncCursor::Start => None,
            // Seconds, and rounded *down*: nostr timestamps have one-second
            // resolution, so a cursor that rounded up would skip every note
            // sharing its second. The repeat is absorbed by the store's digest
            // index; a skipped note would be lost for good.
            SyncCursor::Timestamp(t) => Some(t.utc_millis().max(0).unsigned_abs() / 1_000),
            SyncCursor::Complete => {
                return Ok(empty_batch(SyncCursor::Complete));
            }
            // A file-mtime or opaque cursor belongs to another adapter.
            // Refusing beats guessing: proceeding would re-import the whole
            // feed or skip a span, and both are worse than stopping.
            SyncCursor::FileMtime(_) | SyncCursor::Opaque(_) => {
                return Err(crate::Error::InvalidCursor { id: source.id });
            }
            _ => return Err(crate::Error::InvalidCursor { id: source.id }),
        };

        let filter = Filter {
            authors: vec![author],
            raw_kinds: kinds.clone(),
            since,
            // One past the batch, so "there is more" is observed rather than
            // guessed from a full page.
            limit: u32::try_from(BATCH_NOTES + 1).ok(),
            ..Filter::default()
        };
        let fetched = self
            .client
            .fetch(&filter)
            .await
            .map_err(|_| crate::Error::Unreachable { id: source.id })?;

        let Screened {
            mut kept,
            rejected,
            stale,
        } = screen(fetched, author, kinds, since);

        // Oldest first, then by id: a resumed pull continues where it stopped
        // rather than wherever the relay happened to answer from.
        kept.sort_by(|a, b| {
            a.event
                .created_at
                .cmp(&b.event.created_at)
                .then_with(|| a.id.to_hex().cmp(&b.id.to_hex()))
        });
        let has_more = kept.len() > BATCH_NOTES;
        kept.truncate(BATCH_NOTES);

        let mut memories = Vec::with_capacity(kept.len());
        let mut unparseable = 0u32;
        for event in &kept {
            match to_memory(event, source.id, self.clock.as_ref(), self.rng.as_ref()) {
                Ok(memory) => memories.push(memory),
                Err(_) => unparseable = unparseable.saturating_add(1),
            }
        }

        // Sits *on* the newest note rather than past it, so notes sharing that
        // second cannot be skipped.
        let next = kept.last().map_or(cursor, |e| {
            SyncCursor::Timestamp(created_at_timestamp(e.event.created_at))
        });

        Ok(IngestBatch {
            memories,
            cursor: next,
            has_more,
            // A note from before the cursor is one this adapter has already
            // offered, which is exactly what this field counts.
            duplicates_skipped: stale,
            unparseable_skipped: unparseable,
            rejected_untrusted: rejected,
        })
    }

    fn default_trust(&self) -> TrustLevel {
        default_trust()
    }

    fn default_sensitivity(&self) -> Sensitivity {
        default_sensitivity()
    }

    fn touches_network(&self) -> bool {
        true
    }

    async fn validate(&self, source: &Source) -> crate::Result<()> {
        let SourceKind::NostrFeed {
            pubkey,
            relays,
            kinds,
        } = &source.kind
        else {
            return Err(crate::Error::InvalidCursor { id: source.id });
        };
        validate_config(pubkey, relays, kinds, source.id)
    }
}

/// A batch that produced nothing, leaving the cursor where it was.
fn empty_batch(cursor: SyncCursor) -> IngestBatch {
    IngestBatch {
        memories: Vec::new(),
        cursor,
        has_more: false,
        duplicates_skipped: 0,
        unparseable_skipped: 0,
        rejected_untrusted: 0,
    }
}
