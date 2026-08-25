//! Turning engine output into terminal text.
//!
//! One rule throughout: **never print a number without what qualifies it**. A
//! bare count or a bare "ok" invites a conclusion the evidence may not support,
//! and this project's whole claim rests on its numbers being trustworthy.

use ghostr_core::footage::Thread;
use ghostr_core::persona::{ChangeKind, PersonaDiff, PersonaModel};
use ghostr_core::sensitivity::Sensitivity;
use ghostr_engine::engine::{Engine, InitOutcome};
use ghostr_engine::ops::CandidateVersion;
use ghostr_engine::ops::{IngestReport, Recap, VerifyReport};
use ghostr_engine::sources::{SourcePlan, SyncReport};
use ghostr_engine::types::{AnchorRecord, AnchorRecordState, Footage};
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
        out.push_str(
            "\n  This phrase IS your identity. It is not stored anywhere in\n\
             \x20 readable form and it cannot be regenerated or reset.\n\
             \x20 Anyone who has it can read everything you ever record.\n\
             \x20 Lose it and the vault is unrecoverable — there is no backup\n\
             \x20 and no support address that can help.\n",
        );
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
    out.push_str(&format!(
        "roots   {}\n",
        if !report.chain_ok {
            "not checked (chain failed first)"
        } else if report.roots_ok {
            "OK"
        } else {
            "FAILED"
        }
    ));

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
    let tip = engine.store().tip()?;
    let memories = engine.store().memory_count()?;
    Ok(format!(
        "vault   {}\nnpub    {}\ntz      {}\nmemories {}\ntip     {}\nmodel   none (M0 is offline; no LLM is compiled in)",
        engine.dir().display(),
        engine.npub().as_str(),
        engine.home_tz()?.name(),
        memories,
        tip.map_or_else(
            || "none sealed".to_owned(),
            |t| format!("seq {} · {}", t.seq, t.link.short())
        ),
    ))
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
