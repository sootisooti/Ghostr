//! Turning engine output into terminal text.
//!
//! One rule throughout: **never print a number without what qualifies it**. A
//! bare count or a bare "ok" invites a conclusion the evidence may not support,
//! and this project's whole claim rests on its numbers being trustworthy.

use ghostr_core::fidelity::{FidelityScore, ScoreWindow};
use ghostr_core::footage::Thread;
use ghostr_core::persona::{ChangeKind, PersonaDiff, PersonaModel};
use ghostr_core::quest::{Quest, QuestKind};
use ghostr_core::sensitivity::Sensitivity;
use ghostr_engine::engine::{Engine, InitOutcome};
use ghostr_engine::ops::CandidateVersion;
use ghostr_engine::ops::{IngestReport, QuestIssue, Recap, VerifyReport};
use ghostr_engine::serve::{Bind, Token};
use ghostr_engine::sources::{SourcePlan, SyncReport};
use ghostr_engine::types::{AnchorRecord, AnchorRecordState, Footage};
use ghostr_quests::Presented;
use ghostr_quests::VerdictOutcome;
use ghostr_store::sqlite::{EgressRecord, PersonaSummary, StoredSource};

/// Renders the result of `init`.
///
/// The mnemonic warning is shown at the moment the seed exists, not in a
/// footnote someone reads afterwards. A seed leak is unrecoverable rather than
/// merely bad, and that is not something to bury (THREAT_MODEL §T5).
pub(crate) fn init(engine: &Engine, outcome: &InitOutcome, dir: &std::path::Path) -> String {
    let mut out = String::new();
    out.push_str(&format!("vault created at {}\n", dir.display()));
    out.push_str(&format!("npub    {}\n", outcome.npub.as_str()));
    out.push_str(&format!("genesis {}\n", outcome.genesis_link.short()));
    out.push_str(&format!(
        "cutoff  23:59 {}\n",
        engine
            .home_tz()
            .map(|t| t.name().to_owned())
            .unwrap_or_default()
    ));

    if let Some(phrase) = &outcome.mnemonic {
        out.push_str(
            "\n  RECOVERY PHRASE — write this down now, on paper.\n\
             \n",
        );
        for (i, word) in phrase.split_whitespace().enumerate() {
            out.push_str(&format!("  {:>2}. {word}\n", i + 1));
        }
        // What this phrase *is* depends on where the identity came from, and
        // saying the wrong one is how a key gets lost. On an imported vault the
        // phrase is the seed and the `nsec` is the identity — two secrets, and
        // the user has to be told that plainly (SPEC §14 Q21).
        if outcome.identity_imported {
            out.push_str(
                "\n  You now have TWO things to back up.\n\
                 \n\
                 \x20 1. The nsec you pasted. That is your identity — it signs\n\
                 \x20    as you, and this vault does not store it in any form\n\
                 \x20    you could read back.\n\
                 \x20 2. The phrase above. That is this vault: the journal, the\n\
                 \x20    chain, and the ghost.\n\
                 \n\
                 \x20 Lose the nsec and you keep the journal but can no longer\n\
                 \x20 speak as that identity. Lose the phrase and the journal is\n\
                 \x20 gone — there is no backup and no support address.\n",
            );
        } else {
            out.push_str(
                "\n  This phrase IS your identity. It is not stored anywhere in\n\
                 \x20 readable form and it cannot be regenerated or reset.\n\
                 \x20 Anyone who has it can read everything you ever record.\n\
                 \x20 Lose it and the vault is unrecoverable — there is no backup\n\
                 \x20 and no support address that can help.\n",
            );
        }
    }
    out
}

/// Renders an ingest report.
pub(crate) fn ingest(report: &IngestReport, path: &std::path::Path) -> String {
    let mut out = format!(
        "ingested {} note(s) from {}",
        report.ingested,
        path.display()
    );
    // Skipped is reported rather than hidden: on a second run it is the whole
    // story, and silence would look like the command did nothing.
    if report.skipped > 0 {
        out.push_str(&format!(", {} already present", report.skipped));
    }
    if report.failed > 0 {
        out.push_str(&format!(", {} unreadable", report.failed));
    }
    out
}

/// Renders a freshly sealed footage.
pub(crate) fn sealed(footage: &Footage) -> String {
    format!(
        "sealed seq {} for {} ({})\n  memories   {}\n  highlights {}\n  link       {}\n  prev       {}",
        footage.seq,
        footage.date,
        if footage.empty {
            "empty day"
        } else {
            "compiled"
        },
        footage.memory_ids.len(),
        footage.highlights.len(),
        footage.commitment.link.short(),
        footage.commitment.prev_link.short(),
    )
}

/// Renders the footage list.
pub(crate) fn footage_list(all: &[Footage], anchors: &[Option<AnchorRecord>]) -> String {
    if all.is_empty() {
        return "no footage sealed yet — run `ghostr memoria`".to_owned();
    }
    let mut out = format!(
        "{:<5} {:<12} {:>5} {:>6} {:<10} {}\n",
        "SEQ", "DATE", "MEMS", "HIGHS", "ANCHOR", "LINK"
    );
    for (f, anchor) in all.iter().zip(anchors.iter()) {
        out.push_str(&format!(
            "{:<5} {:<12} {:>5} {:>6} {:<10} {}\n",
            f.seq,
            f.date,
            f.memory_ids.len(),
            f.highlights.len(),
            anchor_label(anchor.as_ref()),
            f.commitment.link.short(),
        ));
    }
    out.trim_end().to_owned()
}

fn anchor_label(anchor: Option<&AnchorRecord>) -> &'static str {
    match anchor.map(|a| a.state) {
        Some(AnchorRecordState::Confirmed) => "confirmed",
        Some(AnchorRecordState::Pending) => "pending",
        Some(AnchorRecordState::Failed) => "failed",
        _ => "-",
    }
}

/// Renders one footage in full.
pub(crate) fn footage_show(footage: &Footage) -> String {
    let mut out = format!(
        "seq {}  {}  {}\n",
        footage.seq,
        footage.date,
        footage.tz.name()
    );
    out.push_str(&format!(
        "link {}\nprev {}\nroot {}\n",
        footage.commitment.link,
        footage.commitment.prev_link.short(),
        footage.commitment.merkle_root.short(),
    ));

    if footage.empty {
        out.push_str("\n(no memories fell in this window; the day still sealed)\n");
        return out;
    }

    if !footage.highlights.is_empty() {
        out.push_str("\nHIGHLIGHTS\n");
        for h in &footage.highlights {
            // Every highlight cites its evidence, so a reader can always ask
            // "where did that come from?" and get an answer.
            out.push_str(&format!(
                "  - {}\n      [{}]\n",
                h.summary,
                h.memory_ids
                    .iter()
                    .map(|m| m.display_short())
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
    }

    if !footage.people.is_empty() {
        out.push_str("\nPEOPLE\n");
        for p in &footage.people {
            out.push_str(&format!(
                "  - {} ({} mention(s))\n",
                p.entity.display_short(),
                p.memory_ids.len()
            ));
        }
    }

    // Confidence travels with the mood, always. A reading drawn from two words
    // and one drawn from twenty deserve different weight, and a bare valence
    // hides that.
    out.push_str(&format!(
        "\nMOOD\n  valence {:+.2}  arousal {:.2}  confidence {:.2}{}\n",
        footage.mood.valence,
        footage.mood.arousal,
        footage.mood.confidence,
        if footage.mood.labels.is_empty() {
            "  (no mood signal found)".to_owned()
        } else {
            format!("  {}", footage.mood.labels.join(", "))
        }
    ));

    if !footage.open_threads.is_empty() {
        out.push_str("\nOPEN THREADS\n");
        for t in &footage.open_threads {
            out.push_str(&format!("  - {} (since seq {})\n", t.title, t.opened_seq));
        }
    }
    if !footage.closed_loops.is_empty() {
        out.push_str(&format!("\nCLOSED TODAY  {}\n", footage.closed_loops.len()));
    }
    if !footage.unresolved.is_empty() {
        out.push_str("\nUNRESOLVED\n");
        for q in &footage.unresolved {
            out.push_str(&format!("  - {}\n", q.question));
        }
    }
    if !footage.amendments.is_empty() {
        // Shown with the day they correct, not just as a count. An amendment
        // whose target is invisible is a correction to nothing in particular.
        out.push_str("\nAMENDMENTS\n");
        for a in &footage.amendments {
            out.push_str(&format!("  - seq {}: {}\n", a.target_seq, a.note));
        }
    }
    out
}

/// Renders an anchoring result.
pub(crate) fn anchor(record: &AnchorRecord) -> String {
    match record.state {
        AnchorRecordState::Pending => format!(
            "seq {} submitted to OpenTimestamps\n  digest {}\n  {}\n\n\
             The proof is pending: calendars aggregate submissions into a Bitcoin\n\
             transaction, which takes hours. The chain is already valid without it.",
            record.seq,
            record.digest.short(),
            record.detail.as_deref().unwrap_or("")
        ),
        AnchorRecordState::Confirmed => format!(
            "seq {} confirmed in block {}",
            record.seq,
            record.block_height.unwrap_or_default()
        ),
        // Offline is a normal outcome, and the message says so rather than
        // reading like a fault the user has to fix.
        AnchorRecordState::Failed => format!(
            "seq {} could not be submitted after {} attempt(s)\n  {}\n\n\
             The chain is unaffected — an unanchored day is still a valid link.\n\
             Re-run `ghostr anchor` when you are online.",
            record.seq,
            record.attempts,
            record.detail.as_deref().unwrap_or("no calendar reachable")
        ),
        // AnchorRecordState is #[non_exhaustive]; an unrecognised state means
        // the day is not attested, which is the safe reading to show.
        _ => format!("seq {} is not anchored", record.seq),
    }
}

/// Renders a verification report.
///
/// States what was checked and what was not. A verifier that overstates its own
/// assurance is worse than one that declines to run.
pub(crate) fn verify(report: &VerifyReport) -> String {
    if report.days == 0 {
        return "nothing sealed yet — nothing to verify".to_owned();
    }
    let mut out = String::new();
    out.push_str(&format!(
        "chain   {}  ({} day(s) from genesis)\n",
        if report.chain_ok { "OK" } else { "FAILED" },
        report.days
    ));
    // Three states, not two. A replica restored from relays holds the footage
    // but not the memories, so its roots cannot be re-derived — saying FAILED
    // there would tell a user their history had been altered when nothing had.
    let roots = if !report.chain_ok {
        "not checked (chain failed first)".to_owned()
    } else if !report.roots_ok {
        "FAILED".to_owned()
    } else if report.roots_unchecked == report.days {
        "not checkable here (this device holds no memories)".to_owned()
    } else if report.roots_unchecked > 0 {
        format!("OK  ({} day(s) not checkable here)", report.roots_unchecked)
    } else {
        "OK".to_owned()
    };
    out.push_str(&format!("roots   {roots}\n"));

    if let Some(seq) = report.first_bad_seq {
        out.push_str(&format!("\nfirst bad sequence: {seq}\n"));
    }
    if let Some(detail) = &report.detail {
        out.push_str(&format!("{detail}\n"));
    }

    out.push_str(&format!(
        "\nanchors {} confirmed, {} pending, {} unanchored\n",
        report.anchored,
        report.pending,
        report.days.saturating_sub(report.anchored + report.pending),
    ));
    // Say plainly what a pending proof does and does not establish.
    if report.pending > 0 {
        out.push_str(
            "\nPending proofs are submitted but not yet in a block, so they do not\n\
             yet establish a time. Upgrading them to a Bitcoin attestation arrives\n\
             with M1.\n",
        );
    }
    out.trim_end().to_owned()
}

/// Renders vault status.
pub(crate) fn status(engine: &Engine) -> anyhow::Result<String> {
    use ghostr_crypto::signer::Keystore as _;

    let tip = engine.store().tip()?;
    let memories = engine.store().memory_count()?;
    Ok(format!(
        "vault   {}\nnpub    {}\ntz      {}\nmemories {}\ntip     {}\nswap    {}\nmodel   none (M0 is offline; no LLM is compiled in)",
        engine.dir().display(),
        engine.npub().as_str(),
        engine.home_tz()?.name(),
        memories,
        tip.map_or_else(
            || "none sealed".to_owned(),
            |t| format!("seq {} · {}", t.seq, t.link.short())
        ),
        swap_protection(engine.keystore().pinned_secrets()),
    ))
}

/// How much of the in-memory key material is pinned out of swap.
///
/// Printed even when everything worked, because the interesting case is the one
/// where it did not and nothing else would say so. An unlocked vault holds six
/// secrets in a page each, and whether the kernel pins them depends on
/// `RLIMIT_MEMLOCK`, on `CAP_IPC_LOCK`, and on the container runtime — so the
/// honest thing is to measure rather than to promise. A short answer is
/// actionable: `ulimit -l` is the knob (THREAT_MODEL §T1).
fn swap_protection((pinned, total): (usize, usize)) -> String {
    match (pinned, total) {
        (_, 0) => "no keys held in this process".to_owned(),
        (p, t) if p == t => format!("{p}/{t} keys pinned out of swap"),
        (0, t) => format!("0/{t} keys pinned — nothing is protected from swap. Raise `ulimit -l`"),
        (p, t) => {
            format!("{p}/{t} keys pinned — the rest can be swapped to disk. Raise `ulimit -l`")
        }
    }
}

/// Renders the result of adding a source.
///
/// States the two things the user is agreeing to — how the content will be
/// trusted, and whether pulling reaches the network — at the moment of the
/// decision, rather than leaving them to be discovered afterwards
/// (THREAT_MODEL §T7).
pub(crate) fn source_added(id: ghostr_core::ids::SourceId, plan: &SourcePlan) -> String {
    format!(
        "added {}  {}\n  trust        {}\n  sensitivity  {}{}\n  network      {}\n",
        id.display_short(),
        plan.kind_tag,
        trust_word(plan.trust),
        sensitivity_word(plan.sensitivity),
        if plan.sensitivity == Sensitivity::Secret {
            "  (never leaves this device)"
        } else {
            ""
        },
        if plan.touches_network {
            "yes — this source will talk to the internet"
        } else {
            "no"
        }
    )
}

/// Renders the configured sources.
pub(crate) fn source_list(sources: &[StoredSource]) -> String {
    if sources.is_empty() {
        return "no sources configured\n  add one with `ghostr source add`\n".to_owned();
    }
    let mut out = format!("{} source(s)\n", sources.len());
    for s in sources {
        out.push_str(&format!(
            "  {}  {:<16} {:<13} {:<7} {}\n",
            s.id.display_short(),
            s.kind_tag,
            trust_word(s.trust),
            sensitivity_word(s.default_sensitivity),
            if s.enabled { "enabled" } else { "disabled" },
        ));
    }
    out
}

/// Renders a sync.
pub(crate) fn source_sync(report: &SyncReport) -> String {
    let mut out = format!(
        "synced {} source(s): {} new, {} already present",
        report.sources, report.ingested, report.skipped
    );
    if report.unparseable > 0 {
        // Named rather than swallowed: an import that silently dropped rows is
        // worse than one that says how many it could not read.
        out.push_str(&format!(", {} unparseable", report.unparseable));
    }
    if report.unreachable > 0 {
        out.push_str(&format!(", {} unreachable", report.unreachable));
    }
    out.push('\n');
    if report.needs_relays > 0 {
        // Not an error and not silence: the feed was never asked. A feed that
        // quietly produces nothing looks exactly like an author who stopped
        // posting, and those are very different facts.
        out.push_str(&format!(
            "{} feed(s) skipped: no relays configured\n",
            report.needs_relays
        ));
    }
    if report.rejected > 0 {
        // The one line here that can mean somebody is trying something: a relay
        // answered a filter with events nobody asked for (THREAT_MODEL §T7).
        out.push_str(&format!(
            "{} event(s) refused: a relay returned what was not asked for\n",
            report.rejected
        ));
    }
    out
}

/// Renders a recap.
pub(crate) fn recap(recap: &Recap) -> String {
    if recap.sealed {
        return footage_show(&recap.footage);
    }
    // Said first, and plainly, and the commitment lines are dropped: a preview
    // has none, and printing a row of zeroes where a link belongs invites
    // someone to copy it as if it were one.
    let mut out = format!(
        "{} is not sealed yet — this is a preview, and nothing here is committed\n\n",
        recap.date
    );
    let full = footage_show(&recap.footage);
    for line in full.lines() {
        if line.starts_with("link ") || line.starts_with("prev ") || line.starts_with("root ") {
            continue;
        }
        out.push_str(line);
        out.push('\n');
    }
    out
}

/// Renders the open threads.
pub(crate) fn thread_list(threads: &[Thread]) -> String {
    if threads.is_empty() {
        return "no open threads\n".to_owned();
    }
    let mut out = format!("{} open thread(s)\n", threads.len());
    for t in threads {
        out.push_str(&format!(
            "  {}  {}\n      opened seq {}, last touched seq {}, {} memory(ies)\n",
            t.id.display_short(),
            t.title,
            t.opened_seq,
            t.last_touched_seq,
            t.memory_ids.len(),
        ));
    }
    out
}

/// Renders the egress log.
///
/// An empty log on a vault that has never used a remote model is the expected
/// answer, and the sentence says so — "nothing" and "not recorded" must not look
/// the same (SPEC I5).
pub(crate) fn egress_log(records: &[EgressRecord]) -> String {
    if records.is_empty() {
        return "nothing has left this device\n  \
                (the log records every decision, allows and denies alike)\n"
            .to_owned();
    }
    let mut out = format!("{} egress decision(s), newest first\n", records.len());
    for r in records {
        out.push_str(&format!(
            "  {}  {:<10} {:<15} {:<15} {} byte(s)",
            r.at.utc_millis(),
            r.decision,
            r.provider,
            r.task,
            r.bytes_sent,
        ));
        if let Some(reason) = &r.deny_reason {
            out.push_str(&format!("  [{reason}]"));
        }
        if r.entities > 0 {
            out.push_str(&format!("  {} name(s) pseudonymised", r.entities));
        }
        out.push('\n');
        if let Some(digest) = &r.payload_digest {
            // The digest, not the payload. The log must not become a second
            // copy of the corpus.
            out.push_str(&format!(
                "      digest {}\n",
                &digest[..16.min(digest.len())]
            ));
        }
    }
    out
}

/// The word for a trust level.
const fn trust_word(t: ghostr_core::sensitivity::TrustLevel) -> &'static str {
    use ghostr_core::sensitivity::TrustLevel;

    match t {
        TrustLevel::FirstParty => "first-party",
        TrustLevel::SelfReported => "self-reported",
        TrustLevel::ThirdParty => "third-party",
    }
}

/// The word for a sensitivity.
const fn sensitivity_word(s: Sensitivity) -> &'static str {
    match s {
        Sensitivity::Public => "public",
        Sensitivity::Private => "private",
        Sensitivity::Secret => "secret",
    }
}

/// Renders a persona.
///
/// Numbers come with what qualifies them, and every claim shows how many
/// memories back it — a stance supported by two notes and one supported by
/// fifty deserve different weight, and a bare position hides that.
pub(crate) fn persona_show(model: &PersonaModel) -> String {
    let v = &model.facets.voice;
    let mut out = format!(
        "{}  distilled from {} memory(ies)\n",
        model.version.display_short(),
        model.derived_from.len()
    );
    if let Some(parent) = model.parent {
        out.push_str(&format!("parent {}\n", parent.display_short()));
    }

    out.push_str("\nVOICE\n");
    out.push_str(&format!(
        "  formality {:.2}  warmth {:.2}  hedging {:.2}  profanity {:.2}\n",
        v.register.formality, v.register.warmth, v.register.hedging, v.register.profanity
    ));
    out.push_str(&format!(
        "  sentences {:.1} words (sd {:.1}), {:.0}% fragments\n",
        v.syntax.mean_sentence_words,
        v.syntax.sentence_words_stddev,
        v.syntax.fragment_rate * 100.0
    ));
    if !v.lexicon.is_empty() {
        let phrases: Vec<&str> = v
            .lexicon
            .iter()
            .take(8)
            .map(|t| t.phrase.as_str())
            .collect();
        out.push_str(&format!("  characteristic words: {}\n", phrases.join(", ")));
    }
    out.push_str(&format!("  {} exemplar(s)\n", v.exemplars.len()));

    if model.facets.opinions.is_empty() {
        // Said out loud rather than left as an empty heading. "No model
        // configured" and "this person holds no views" are different facts.
        out.push_str(
            "\nOPINIONS\n  none recorded (these need a model; run with --features llm-local)\n",
        );
    } else {
        out.push_str("\nOPINIONS\n");
        for s in &model.facets.opinions {
            out.push_str(&format!(
                "  - {}: {} (strength {:.2}, {} memory(ies)",
                s.topic,
                s.position,
                s.strength,
                s.evidence.len()
            ));
            if !s.contradicted_by.is_empty() {
                out.push_str(&format!(", {} contradicting", s.contradicted_by.len()));
            }
            out.push_str(")\n");
        }
    }

    if !model.facets.relationships.is_empty() {
        out.push_str("\nPEOPLE\n");
        for r in model.facets.relationships.iter().take(10) {
            out.push_str(&format!(
                "  - {}  closeness {:.2}, {} memory(ies)",
                r.entity.display_short(),
                r.closeness,
                r.evidence.len()
            ));
            if let Some(days) = r.cadence_days {
                out.push_str(&format!(", about every {days:.0} day(s)"));
            }
            out.push('\n');
        }
    }

    if !model.facets.routines.is_empty() {
        out.push_str("\nROUTINES\n");
        for r in &model.facets.routines {
            out.push_str(&format!(
                "  - {} — {} (confidence {:.2})\n",
                r.pattern, r.schedule, r.confidence
            ));
        }
    }
    out
}

/// Renders a proposed version and whether it needs reading.
pub(crate) fn persona_candidate(candidate: &CandidateVersion) -> String {
    let mut out = format!("proposed {}\n", candidate.model.version.display_short());
    if let Some(replaces) = candidate.replaces {
        out.push_str(&format!("replaces {}\n", replaces.display_short()));
    }
    out.push('\n');
    out.push_str(&persona_diff(&candidate.diff));

    if candidate.warrants_review {
        // The whole point of separating proposal from adoption: a large change
        // should not take effect because nobody looked.
        out.push_str("\nthis is a substantial change — read it before adopting\n");
    }
    out.push_str("\nadopt with `ghostr persona adopt`\n");
    out
}

/// Renders a diff.
pub(crate) fn persona_diff(diff: &PersonaDiff) -> String {
    if diff.changes.is_empty() {
        return format!(
            "{} → {}: nothing changed\n",
            diff.from.display_short(),
            diff.to.display_short()
        );
    }
    let mut out = format!(
        "{} → {}: {} change(s)\n",
        diff.from.display_short(),
        diff.to.display_short(),
        diff.changes.len()
    );
    for change in &diff.changes {
        out.push_str(&format!(
            "  [{}] {}\n",
            change_word(change.kind),
            change.description
        ));
        if !change.caused_by.is_empty() {
            // The audit trail: which note caused this. It is what makes a
            // poisoned belief traceable rather than merely present.
            out.push_str(&format!(
                "      because of {}\n",
                change
                    .caused_by
                    .iter()
                    .take(4)
                    .map(ghostr_core::ids::MemoryId::display_short)
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
    }
    out
}

/// Renders the version history.
pub(crate) fn persona_history(versions: &[PersonaSummary]) -> String {
    if versions.is_empty() {
        return "no persona distilled yet\n  run `ghostr persona distill`\n".to_owned();
    }
    let mut out = format!("{} version(s), newest first\n", versions.len());
    for v in versions {
        out.push_str(&format!(
            "  v{:<4} {}  {}{}\n",
            v.ordinal,
            &v.content[..8.min(v.content.len())],
            v.created_at.to_utc().format("%Y-%m-%d %H:%M"),
            if v.is_head { "  (head)" } else { "" }
        ));
    }
    out
}

/// The word for a change kind.
const fn change_word(kind: ChangeKind) -> &'static str {
    match kind {
        ChangeKind::Added => "added",
        ChangeKind::Removed => "removed",
        ChangeKind::Adjusted => "adjusted",
        ChangeKind::Reversed => "reversed",
        ChangeKind::Contradicted => "contradicted",
        _ => "changed",
    }
}

/// Renders what `quest issue` produced.
///
/// Counts and ids, never the claims. The claims are the ghost's committed
/// answers, and printing them at issue time would hand the user the answer key
/// before they had answered anything (I6).
pub(crate) fn quest_issue(issue: &QuestIssue) -> String {
    let mut out = format!(
        "issued {} quest(s) for {} under {}\n",
        issue.issued.len(),
        issue.date,
        issue.persona_version.display_short()
    );
    if issue.expired > 0 {
        out.push_str(&format!("closed {} stale quest(s) first\n", issue.expired));
    }
    if issue.issued.is_empty() {
        out.push_str(
            "  nothing to ask — the persona has no facet with evidence behind it yet\n  \
             ingest more, seal a few days, then `ghostr persona distill`\n",
        );
    } else {
        out.push_str("\n  answer them with `ghostr quest list`\n");
    }
    out
}

/// Renders the open quests.
pub(crate) fn quest_list(quests: &[Quest]) -> String {
    if quests.is_empty() {
        return "no open quests\n  issue today's with `ghostr quest issue`".to_owned();
    }

    let mut out = format!("{} open quest(s)\n\n", quests.len());
    for quest in quests {
        out.push_str(&format!(
            "{}  {:?}  {}\n",
            quest.id.display_short(),
            quest.facet,
            quest.kind.variant_name()
        ));
        for line in question(&quest.kind).lines() {
            out.push_str(&format!("    {line}\n"));
        }
        out.push('\n');
    }
    out.push_str("answer with `ghostr quest answer <id> confirm|correct|reject|unknown|void`\n");
    out
}

/// Renders one quest in full.
pub(crate) fn quest_show(quest: &Quest) -> String {
    let mut out = format!(
        "{}  {:?}  {}\n",
        quest.id.display_short(),
        quest.facet,
        quest.kind.variant_name()
    );
    out.push_str(&format!(
        "issued {} for {}, expires {}\n",
        local(quest.issued_at),
        quest.issued_for,
        local(quest.expires_at)
    ));
    out.push_str(&format!(
        "asked by {}, over {} memory(ies)\n",
        quest.persona_version.display_short(),
        quest.evidence.len()
    ));
    out.push_str(&format!("commitment {}\n", quest.answer_commitment.short()));
    out.push_str(&format!("\n{}\n", question(&quest.kind)));

    match &quest.verdict {
        // Confidence is shown only after the verdict. Calibration is measurable
        // only if the ghost's stated confidence did not influence the outcome it
        // predicts (SPEC Q17).
        Some(verdict) => out.push_str(&format!(
            "\nanswered: {verdict:?}\n  the ghost was {:.0}% sure\n",
            quest.confidence * 100.0
        )),
        None => out.push_str("\nunanswered\n"),
    }
    out
}

/// A timestamp in the offset it was recorded at.
fn local(at: ghostr_core::time::Timestamp) -> String {
    at.to_local().format("%Y-%m-%d %H:%M").to_string()
}

/// What the user is asked, with nothing they should not see yet.
///
/// The decision about what may be shown is not made here. It is made once, in
/// [`ghostr_quests::present`], so that this renderer and the local API's cannot
/// disagree about it — and the one that disagrees is always the newer one,
/// written by someone who did not know the rule existed (I6).
fn question(kind: &QuestKind) -> String {
    match ghostr_quests::present(kind) {
        Presented::Assertion {
            prompt,
            ghost_answer,
        } => format!("on \"{prompt}\", the ghost says:\n\"{ghost_answer}\""),
        Presented::Claim { text, when } => format!("{when}: {text}"),
        Presented::Choice { a, b } => {
            format!("A: {a}\nB: {b}\n(the ghost has picked one; it is sealed until you answer)")
        }
        Presented::Gap { before, after } => format!("fill the gap: {before}___{after}"),
        // `Unrenderable` and any variant a later version adds land together:
        // showing nothing is the only safe rendering of a shape this build does
        // not understand.
        Presented::Unrenderable | _ => {
            "(this build cannot show this quest safely; answer `void`)".to_owned()
        }
    }
}

/// Renders the result of a verdict.
pub(crate) fn quest_answered(quest: &Quest, outcome: &VerdictOutcome) -> String {
    let mut out = format!("recorded on {}\n", quest.id.display_short());
    out.push_str(&format!(
        "the ghost was {:.0}% sure\n",
        quest.confidence * 100.0
    ));

    if outcome.decoy_confirmed {
        // Said now, not only in the monthly aggregate. A user who is
        // rubber-stamping benefits from finding out today.
        out.push_str(
            "\n  that claim was a deliberate decoy, and you confirmed it.\n  \
             Decoys exist to catch exactly this; the rate is published beside your score.\n",
        );
    }
    if outcome.suspiciously_fast {
        out.push_str("\n  answered faster than a plausible read; flagged, not discounted\n");
    }

    out.push_str(&format!(
        "\nscored: {}\n",
        if outcome.scored {
            "yes — this one counts toward fidelity"
        } else {
            "no — this one trains the ghost instead"
        }
    ));
    if outcome.memory.is_some() {
        out.push_str("your correction is now part of the corpus\n");
    }
    if outcome.delta.is_some() {
        out.push_str("queued against the persona; applied at the next distillation\n");
    }
    out
}

/// Renders a fidelity score, never as a bare percentage.
///
/// The interval, the sample size, and the integrity signals travel with the
/// number every time it is shown. 100% over four quests is noise, and 92% with
/// a 30% decoy-confirm rate is a lie (SPEC §3.7).
pub(crate) fn fidelity(score: &FidelityScore) -> String {
    let pct = |x: f32| format!("{:.0}%", x * 100.0);
    let window = match score.window {
        ScoreWindow::Rolling30 => "last 30 days",
        ScoreWindow::Rolling90 => "last 90 days",
        _ => "all time",
    };

    let mut out = format!(
        "{} over {} held-out quest(s), {}\n",
        pct(score.overall),
        score.sample_size,
        window
    );
    out.push_str(&format!(
        "95% interval {}–{}\n",
        pct(score.confidence_interval.0),
        pct(score.confidence_interval.1)
    ));
    // The direction, beside the level (SPEC §5.2). Which way the number is
    // moving is what a daily loop is for; a user cannot tell an improving 72%
    // from a decaying one, and that difference matters more than the 72%.
    if let Some(trend) = score.trend {
        let delta = trend - score.overall;
        // Named rather than signed, because a reader should not have to work
        // out which way a minus sign points on a smoothed average.
        let direction = if delta.abs() < 0.01 {
            "level"
        } else if delta > 0.0 {
            "recent days above the window"
        } else {
            "recent days below the window"
        };
        out.push_str(&format!(
            "trend        {} (30-day EWMA) — {direction}\n",
            pct(trend)
        ));
    } else {
        // Said rather than omitted: a missing line reads as "no trend", and
        // "one day of quests" is a different fact.
        out.push_str("trend        not yet — a trend needs more than one day\n");
    }
    out.push_str(&format!(
        "calibration: Brier {:.3}, ECE {:.3} over {} pair(s)\n",
        score.calibration.brier, score.calibration.ece, score.calibration.sample_size
    ));
    out.push_str(&format!("at chain seq {}\n", score.committed_at_seq));

    if !score.by_facet.is_empty() {
        out.push_str("\nBY FACET\n");
        for (facet, slice) in &score.by_facet {
            out.push_str(&format!(
                "  {:<13} {} over {} ({}–{})\n",
                format!("{facet:?}"),
                pct(slice.score),
                slice.sample_size,
                pct(slice.confidence_interval.0),
                pct(slice.confidence_interval.1)
            ));
        }
    }

    if !score.by_quest_kind.is_empty() {
        out.push_str("\nBY KIND\n");
        for (kind, slice) in &score.by_quest_kind {
            out.push_str(&format!(
                "  {:<15} {} over {}\n",
                format!("{kind:?}"),
                pct(slice.score),
                slice.sample_size
            ));
        }
    }

    let i = &score.integrity;
    out.push_str("\nINTEGRITY\n");
    out.push_str(&format!(
        "  decoys confirmed  {} of {}\n",
        pct(i.decoy_confirm_rate),
        i.decoy_sample_size
    ));
    out.push_str(&format!(
        "  fast verdicts     {}\n",
        pct(i.fast_verdict_rate)
    ));
    out.push_str(&format!(
        "  longest confirm streak  {}\n",
        i.longest_confirm_streak
    ));
    out.push_str(&format!(
        "  expired unanswered      {}\n",
        pct(i.expiry_rate)
    ));

    out.push_str(&format!(
        "\nconverged: {}\n",
        if score.converged {
            "yes"
        } else {
            "not yet — see SPEC §5.3 for what is still missing"
        }
    ));
    out
}

/// What `serve` prints when it starts.
///
/// The token is printed here and nowhere else — not into a log, not into a
/// file. It is in the URL fragment rather than the path, because a browser
/// never sends a fragment to a server and a proxy never logs one, so a token in
/// a path would end up in every access log that saw the request.
///
/// # Errors
///
/// Returns an error if the local addresses cannot be read.
/// The first URL the banner offers, which is the one the QR code encodes.
fn first_url(bind: &Bind, token: &Token) -> Option<String> {
    let addr = bind.http?;
    if ghostr_engine::serve::is_loopback(&addr) {
        // A loopback URL in a QR code is useless to a phone — it would resolve
        // to the phone itself. Offered anyway: it is still the correct URL for
        // this machine, and a camera pointed at it on a laptop screen opens the
        // right page on that laptop.
        return Some(format!("http://{addr}/#t={}", token.expose()));
    }
    local_addresses(addr.port())
        .into_iter()
        .next()
        .map(|host| format!("http://{host}/#t={}", token.expose()))
}

/// Renders a URL as a QR code in unicode half-blocks.
///
/// Returns `None` rather than failing the whole banner: a URL too long to
/// encode, or any other encoder complaint, should cost the convenience and not
/// the thing the user actually came for, which is the URL printed above it.
fn qr_block(url: &str) -> Option<String> {
    use qrcode::render::unicode;

    let code = qrcode::QrCode::new(url.as_bytes()).ok()?;
    let rendered = code
        .render::<unicode::Dense1x2>()
        // Two modules of quiet zone rather than the standard four: a terminal
        // is not paper, and a code that scrolls off the top scans no better for
        // being correctly margined.
        .quiet_zone(true)
        .module_dimensions(1, 1)
        .build();

    // Indented to sit under the surrounding banner text.
    Some(
        rendered
            .lines()
            .map(|line| format!("  {line}\n"))
            .collect::<String>(),
    )
}

pub(crate) fn serve_banner(
    dir: &std::path::Path,
    bind: &Bind,
    token: &Token,
) -> anyhow::Result<String> {
    let mut out = format!(
        "listening on {}\n",
        dir.join(ghostr_engine::serve::SOCKET_FILENAME).display()
    );
    out.push_str("  a unix socket: no port, no network, owner-only\n");

    match bind.http {
        None => {
            out.push_str(
                "\nno browser listener. `ghostr serve --http` adds one on this machine only,\n\
                 and `--http 0.0.0.0:7749 --lan` puts it on the wifi for a phone.\n",
            );
        }
        Some(addr) => {
            out.push('\n');
            if ghostr_engine::serve::is_loopback(&addr) {
                out.push_str(&format!("open  http://{addr}/#t={}\n", token.expose()));
                out.push_str("  this machine only\n");
            } else {
                // The warning goes where the decision is being made, not into a
                // footnote somebody reads afterwards.
                out.push_str(&format!(
                    "  THIS VAULT IS NOW ON THE NETWORK, at {addr}.\n\n  \
                     Anyone who can reach that address and holds the token below can read\n  \
                     your memories, your quests, and your score. The token is the only thing\n  \
                     stopping them, and it is in plaintext HTTP — anyone watching the wifi\n  \
                     sees it. Use this on a network you trust, and stop it when you are done.\n\n"
                ));
                for host in local_addresses(addr.port()) {
                    out.push_str(&format!("open  http://{host}/#t={}\n", token.expose()));
                }
            }
            out.push_str(
                "\n  the token is in the URL fragment, which browsers never send to a\n  \
                          server and proxies never log. It is printed once, here.\n",
            );

            // A QR code, because the alternative is typing a 64-character token
            // on a phone keyboard. That is the single thing standing between
            // "the loop runs" and "the loop runs on the device you actually
            // carry", and it is worth one small dependency.
            //
            // The first URL is the one encoded: on a LAN bind there may be
            // several addresses and only one can be a code, so it is the first
            // one printed rather than an arbitrary pick.
            if let Some(code) = first_url(bind, token).as_deref().and_then(qr_block) {
                out.push_str("\n  point a phone camera at this:\n\n");
                out.push_str(&code);
            }
        }
    }

    out.push_str("\nctrl-c to stop\n");
    Ok(out)
}

/// The addresses a phone on the same network could use.
///
/// Best effort: a wildcard bind reaches every interface, and naming them is
/// more useful than printing `0.0.0.0` and leaving the user to find out their
/// own address.
fn local_addresses(port: u16) -> Vec<String> {
    // Resolving the machine's own hostname is the one portable way to do this
    // without a dependency. A machine whose hostname does not resolve gets the
    // literal bind address instead, which still works once the user knows their
    // own IP.
    let mut out = Vec::new();
    if let Ok(name) = std::env::var("HOSTNAME")
        .or_else(|_| std::fs::read_to_string("/etc/hostname").map(|s| s.trim().to_owned()))
        && !name.is_empty()
    {
        out.push(format!("{name}.local:{port}"));
    }
    if out.is_empty() {
        out.push(format!("<this machine's address>:{port}"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The reporting line is the deliverable, not the lock.
    ///
    /// `mlock` succeeding cannot be asserted — it depends on `RLIMIT_MEMLOCK`,
    /// on `CAP_IPC_LOCK` and on the runtime, and a test that demanded success
    /// would be the flaky kind CLAUDE.md §6 calls a design bug. Measured on this
    /// machine, every page pinned even unprivileged under `ulimit -l 8192`, so
    /// the *failure* path cannot be produced here at all.
    ///
    /// What can be pinned down is that each outcome says something different,
    /// and that a partial or absent lock never reads as success. That is the
    /// part a user's trust actually rests on.
    #[test]
    fn a_partial_lock_never_reads_as_a_full_one() {
        let all = swap_protection((6, 6));
        let some = swap_protection((2, 6));
        let none = swap_protection((0, 6));
        let empty = swap_protection((0, 0));

        assert!(all.contains("6/6"));
        assert!(
            !all.contains("swapped") && !all.contains("ulimit"),
            "a full lock must not warn: {all}"
        );

        for (label, line) in [("partial", &some), ("none", &none)] {
            assert!(
                line.contains("ulimit"),
                "the {label} case must name the knob: {line}"
            );
        }
        assert!(
            some.contains("2/6") && some.contains("the rest"),
            "a partial lock must say how much is unprotected: {some}"
        );
        assert!(
            none.contains("nothing is protected"),
            "no lock at all must say so plainly: {none}"
        );

        // A remote signer holds nothing locally, and "0 of 0" would read as a
        // failure rather than as the correct answer.
        assert!(empty.contains("no keys held"), "{empty}");
        assert!(!empty.contains("ulimit"), "nothing to fix here: {empty}");
    }
}
