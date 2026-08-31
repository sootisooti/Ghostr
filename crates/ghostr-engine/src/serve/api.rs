//! Routing, and the JSON the page reads.
//!
//! # Every response is built from a view, never from a domain type
//!
//! No `Quest`, `Memory`, or `PersonaModel` is serialised directly. They derive
//! `Serialize` for storage, where the row is encrypted; sending one over a
//! socket would put the ghost's committed answer on the wire the moment
//! somebody added a field (I6, I8). The structs here are the wire format, and
//! they carry only what a screen needs.

use ghostr_core::ids::QuestId;
use serde::Serialize;

use super::Token;
use super::http::{Method, Request, Status, error_response, refusal, response};
use crate::engine::Engine;

/// `application/json`, spelled once.
const JSON: &str = "application/json; charset=utf-8";
/// `text/html`, spelled once.
const HTML: &str = "text/html; charset=utf-8";
/// The manifest's media type, which browsers are strict about.
const MANIFEST_TYPE: &str = "application/manifest+json; charset=utf-8";
/// `image/svg+xml`, for the browser tab.
const SVG: &str = "image/svg+xml";
/// `image/png`, for the Home Screen.
const PNG: &str = "image/png";

/// What makes an installed copy look like an app rather than a page.
///
/// `standalone` is what removes the browser chrome once it is on a Home
/// Screen, which is the difference between a daily habit and a bookmark
/// somebody opens twice.
const MANIFEST: &str = r##"{
  "name": "Ghostr",
  "short_name": "ghost",
  "start_url": "/",
  "scope": "/",
  "display": "standalone",
  "orientation": "portrait",
  "background_color": "#0d0e12",
  "theme_color": "#0d0e12",
  "icons": [
    { "src": "/icon.png", "sizes": "180x180", "type": "image/png", "purpose": "any" },
    { "src": "/icon.svg", "sizes": "any", "type": "image/svg+xml", "purpose": "any" }
  ]
}"##;

/// Dispatches one request.
#[must_use]
pub fn route(engine: &Engine, token: &Token, request: &Request<'_>, ui: &str) -> Vec<u8> {
    // The page itself carries no data — it fetches everything — so it is served
    // without a token. Requiring one here would mean putting the token in the
    // URL, where it would land in browser history and every proxy log.
    // The page and its furniture carry no vault data — the page fetches
    // everything — so they are served without a token. Requiring one would mean
    // putting the token in the URL path, where it would land in browser history
    // and every proxy log; and an icon fetched by the Home Screen has no way to
    // present one anyway.
    if request.method == Method::Get {
        match request.path.as_str() {
            "/" | "/index.html" => return response(Status::Ok, HTML, ui.as_bytes()),
            "/manifest.webmanifest" => {
                return response(Status::Ok, MANIFEST_TYPE, MANIFEST.as_bytes());
            }
            "/icon.svg" => return response(Status::Ok, SVG, super::icon::SVG.as_bytes()),
            "/icon.png" => return response(Status::Ok, PNG, &super::icon::png()),
            _ => {}
        }
    }

    // A cross-origin page must not be able to reach this, even holding a
    // guessed token. There are no CORS headers on any response, so a browser
    // will not surface the body — but refusing outright means a request that
    // *writes* never runs at all.
    //
    // Checked against `Host` rather than by presence: browsers attach `Origin`
    // to every POST, same-origin ones included, so refusing any request that
    // carries one refuses the page's own writes while every read keeps working.
    if let Some(origin) = request.origin
        && !super::http::same_origin(origin, request.host)
    {
        return refusal(Status::Forbidden, "cross_origin");
    }

    match request.bearer {
        Some(presented) if token.matches(presented) => {}
        _ => return error_response(Status::Unauthorized),
    }

    let Some(rest) = request.path.strip_prefix("/api/") else {
        return error_response(Status::NotFound);
    };

    let result = match (request.method, rest) {
        (Method::Get, "status") => status(engine),
        (Method::Get, "quests") => quests(engine),
        (Method::Get, "fidelity") => fidelity(engine),
        (Method::Post, "quests/issue") => issue(engine),
        (Method::Get, "recap") => recap(engine),
        (Method::Post, "journal") => journal(engine, request.body),
        (Method::Post, path) => match path.strip_prefix("quests/") {
            Some(id) => answer(engine, id, request.body),
            None => return error_response(Status::NotFound),
        },
        _ => return error_response(Status::NotFound),
    };

    match result {
        Ok(body) => response(Status::Ok, JSON, body.as_bytes()),
        Err(Status::Forbidden) => refusal(Status::Forbidden, "commitment_mismatch"),
        Err(status) => error_response(status),
    }
}

/// Turns an engine error into a status, saying nothing about what was in it.
///
/// The mapping is deliberately coarse. A response that distinguished "no such
/// quest" from "that quest is held out" would answer questions about the vault
/// for someone who has not proved they may ask any (I8).
fn classify(error: &crate::Error) -> Status {
    use ghostr_quests::Error as QuestError;

    match error {
        crate::Error::Quests(QuestError::AlreadyAnswered { .. } | QuestError::Expired { .. }) => {
            Status::Conflict
        }
        crate::Error::Quests(QuestError::CommitmentMismatch { .. }) => Status::Forbidden,
        // The rule name is what separates this from a cross-origin refusal,
        // which shares its status.
        crate::Error::Quests(QuestError::InsufficientSample { .. }) => Status::Unprocessable,
        crate::Error::Config { .. } => Status::Unprocessable,
        crate::Error::Locked => Status::Unauthorized,
        _ => Status::ServerError,
    }
}

/// Encodes a view, or reports the failure as a server error.
fn encode<T: Serialize>(value: &T) -> Result<String, Status> {
    serde_json::to_string(value).map_err(|_| Status::ServerError)
}

/// What the header shows.
#[derive(Serialize)]
struct StatusView {
    npub: String,
    /// Sealed days on the chain.
    sealed_days: u64,
    /// The current persona ordinal, if one has been adopted.
    persona: Option<u32>,
    /// Quests waiting for a verdict.
    open_quests: usize,
    /// Corrections waiting for the next distillation.
    queued_corrections: u32,
    /// Today, in the vault's home timezone rather than the phone's.
    today: String,
}

fn status(engine: &Engine) -> Result<String, Status> {
    let build = || -> crate::Result<StatusView> {
        let tz = engine.home_tz()?;
        Ok(StatusView {
            npub: engine.npub().as_str().to_owned(),
            sealed_days: engine.store().tip()?.map_or(0, |tip| tip.seq),
            persona: crate::ops::persona_head(engine)?.map(|p| p.version.ordinal),
            open_quests: crate::ops::open_quests(engine, 100)?.len(),
            queued_corrections: engine.store().queued_delta_count()?,
            today: engine.now().date_in(&tz).to_string(),
        })
    };
    build().map_err(|e| classify(&e)).and_then(|v| encode(&v))
}

/// One quest, in the form a screen may show before a verdict.
#[derive(Serialize)]
struct QuestView {
    id: String,
    facet: String,
    kind: String,
    /// `claim`, `assertion`, `choice`, `gap`, or `unrenderable`.
    shape: &'static str,
    /// The claim, the scenario, or the sentence around the gap.
    prompt: String,
    /// The ghost's answer, only where the answer *is* the question.
    ghost_answer: Option<String>,
    /// The `when` of a claim, or the second half of a gap.
    tail: Option<String>,
    /// The two options of a choice. Which one the ghost picked is not here.
    options: Option<[String; 2]>,
    expires_at: String,
}

/// Builds the wire form of a quest.
///
/// Reads [`ghostr_quests::present`] and nothing else. The rule about what may
/// be shown lives there, so this cannot disagree with the CLI about it (I6).
fn quest_view(quest: &ghostr_core::quest::Quest) -> QuestView {
    use ghostr_quests::Presented;

    let mut view = QuestView {
        id: quest.id.to_string(),
        facet: format!("{:?}", quest.facet),
        kind: quest.kind.variant_name().to_owned(),
        shape: "unrenderable",
        prompt: String::new(),
        ghost_answer: None,
        tail: None,
        options: None,
        expires_at: quest.expires_at.to_local().to_rfc3339(),
    };

    match ghostr_quests::present(&quest.kind) {
        Presented::Claim { text, when } => {
            view.shape = "claim";
            view.prompt = text;
            view.tail = Some(when);
        }
        Presented::Assertion {
            prompt,
            ghost_answer,
        } => {
            view.shape = "assertion";
            view.prompt = prompt;
            view.ghost_answer = Some(ghost_answer);
        }
        Presented::Choice { a, b } => {
            view.shape = "choice";
            view.options = Some([a, b]);
        }
        Presented::Gap { before, after } => {
            view.shape = "gap";
            view.prompt = before;
            view.tail = Some(after);
        }
        // `Unrenderable`, and any variant a later version adds. The defaults
        // above already say nothing, which is the only safe rendering of a
        // shape this build does not understand.
        _ => {}
    }
    view
}

fn quests(engine: &Engine) -> Result<String, Status> {
    let open = crate::ops::open_quests(engine, 50).map_err(|e| classify(&e))?;
    let views: Vec<QuestView> = open.iter().map(quest_view).collect();
    encode(&views)
}

/// What `issue` produced. Ids and counts, never claims.
#[derive(Serialize)]
struct IssueView {
    date: String,
    issued: usize,
    expired: u64,
}

fn issue(engine: &Engine) -> Result<String, Status> {
    let build = || -> crate::Result<IssueView> {
        let tz = engine.home_tz()?;
        let outcome = crate::ops::issue_quests(engine, engine.now().date_in(&tz))?;
        Ok(IssueView {
            date: outcome.date.to_string(),
            issued: outcome.issued.len(),
            expired: outcome.expired,
        })
    };
    build().map_err(|e| classify(&e)).and_then(|v| encode(&v))
}

/// The verdict a client sends.
#[derive(serde::Deserialize)]
struct AnswerBody {
    /// `confirm`, `correct`, `reject`, `unknown`, or `void`.
    verdict: String,
    /// The correction, the note, or the reason.
    #[serde(default)]
    text: Option<String>,
    /// `minor` or `major`, for a correction.
    #[serde(default)]
    severity: Option<String>,
}

/// What a verdict produced, and what the user is owed straight away.
#[derive(Serialize)]
struct AnsweredView {
    scored: bool,
    decoy_confirmed: bool,
    suspiciously_fast: bool,
    /// Shown only now: confidence must not influence the outcome it predicts
    /// (SPEC Q17).
    ghost_confidence: f32,
    /// Which option the ghost picked, revealed with the verdict.
    ghost_choice: Option<String>,
    /// The word a cloze was asking for, revealed with the verdict.
    ghost_answer: Option<String>,
    stored_correction: bool,
    queued_delta: bool,
}

fn answer(engine: &Engine, id: &str, body: &[u8]) -> Result<String, Status> {
    let Some(id) = id.strip_suffix("/answer") else {
        return Err(Status::NotFound);
    };
    let id = QuestId::parse(id).map_err(|_| Status::BadRequest)?;
    let body: AnswerBody = serde_json::from_slice(body).map_err(|_| Status::BadRequest)?;
    let verdict = parse_verdict(&body)?;

    let build = || -> crate::Result<AnsweredView> {
        let quest = crate::ops::get_quest(engine, id)?;
        let outcome = crate::ops::answer_quest(engine, id, verdict)?;
        Ok(AnsweredView {
            scored: outcome.scored,
            decoy_confirmed: outcome.decoy_confirmed,
            suspiciously_fast: outcome.suspiciously_fast,
            ghost_confidence: quest.confidence,
            // Read only after the write succeeded, so a rejected verdict never
            // reveals the answer it was rejected for.
            ghost_choice: ghostr_quests::view::revealed_choice(&quest.kind)
                .map(|c| format!("{c:?}")),
            ghost_answer: (!quest.kind.reveals_answer_upfront())
                .then(|| quest.kind.committed_answer().to_owned()),
            stored_correction: outcome.memory.is_some(),
            queued_delta: outcome.delta.is_some(),
        })
    };
    build().map_err(|e| classify(&e)).and_then(|v| encode(&v))
}

/// Turns the wire words into a verdict.
fn parse_verdict(body: &AnswerBody) -> Result<ghostr_core::quest::Verdict, Status> {
    use ghostr_core::quest::{Severity, Verdict};

    let words = || -> Result<String, Status> {
        match body
            .text
            .as_deref()
            .map(str::trim)
            .filter(|t| !t.is_empty())
        {
            Some(t) => Ok(t.to_owned()),
            // A correction with no words would be the ghost putting text in its
            // owner's mouth.
            None => Err(Status::BadRequest),
        }
    };

    Ok(match body.verdict.trim().to_lowercase().as_str() {
        "confirm" => Verdict::Confirm,
        "correct" => Verdict::Correct {
            correction: words()?,
            severity: match body.severity.as_deref().unwrap_or("minor") {
                "major" => Severity::Major,
                "minor" => Severity::Minor,
                _ => return Err(Status::BadRequest),
            },
        },
        "reject" => Verdict::Reject {
            note: body
                .text
                .as_deref()
                .map(str::trim)
                .filter(|t| !t.is_empty())
                .map(str::to_owned),
        },
        "unknown" => Verdict::Unknown,
        "void" => Verdict::Void { reason: words()? },
        _ => return Err(Status::BadRequest),
    })
}

/// What the user types on their phone.
#[derive(serde::Deserialize)]
struct JournalBody {
    text: String,
}

/// What an entry produced. The id, never the words back.
#[derive(Serialize)]
struct JournalView {
    id: String,
    /// Where it landed, which is the thing worth confirming.
    stored: &'static str,
}

/// Records a journal entry typed into the page.
///
/// This is the only endpoint that *writes memory content*, and it is what makes
/// the phone a client rather than a window: a thought recorded where it
/// happened, rather than remembered until the user is next at a keyboard.
///
/// The entry goes straight into the encrypted store. It is never written to a
/// plaintext file, not even a temporary one (I1), and the response echoes the
/// id rather than the text — there is no reason to send a memory back over a
/// socket it just arrived on.
fn journal(engine: &Engine, body: &[u8]) -> Result<String, Status> {
    let body: JournalBody = serde_json::from_slice(body).map_err(|_| Status::BadRequest)?;
    if body.text.trim().is_empty() {
        return Err(Status::BadRequest);
    }
    let id = crate::ops::journal_add(engine, &body.text).map_err(|e| classify(&e))?;
    encode(&JournalView {
        id: id.to_string(),
        stored: "encrypted, on this device",
    })
}

/// The day, as a screen can show it.
#[derive(Serialize)]
struct RecapView {
    date: String,
    sealed: bool,
    empty: bool,
    highlights: Vec<String>,
    people: usize,
    mood: Option<MoodView>,
    open_threads: Vec<String>,
    closed_today: usize,
}

#[derive(Serialize)]
struct MoodView {
    valence: f32,
    arousal: f32,
    labels: Vec<String>,
    /// `stated` or `inferred`. The user is the authority on how their day felt,
    /// and a screen that did not say which was which would be presenting the
    /// ghost's guess as their own words.
    basis: String,
}

fn recap(engine: &Engine) -> Result<String, Status> {
    let build = || -> crate::Result<RecapView> {
        let tz = engine.home_tz()?;
        let recap = crate::ops::recap(engine, engine.now().date_in(&tz))?;
        let f = &recap.footage;
        Ok(RecapView {
            date: recap.date.to_string(),
            sealed: recap.sealed,
            empty: f.empty,
            highlights: f.highlights.iter().map(|h| h.summary.clone()).collect(),
            people: f.people.len(),
            mood: (f.mood.confidence > 0.0).then(|| MoodView {
                valence: f.mood.valence,
                arousal: f.mood.arousal,
                labels: f.mood.labels.clone(),
                basis: format!("{:?}", f.mood.basis).to_lowercase(),
            }),
            open_threads: f.open_threads.iter().map(|t| t.title.clone()).collect(),
            closed_today: f.closed_loops.len(),
        })
    };
    build().map_err(|e| classify(&e)).and_then(|v| encode(&v))
}

/// A score, with everything that qualifies it.
///
/// The interval, the sample size, and the integrity signals are not optional
/// fields. A client that could ask for the number alone would eventually be
/// written, and it would be wrong (SPEC §3.7).
#[derive(Serialize)]
struct FidelityView {
    overall: f32,
    sample_size: u32,
    interval: (f32, f32),
    brier: f32,
    ece: f32,
    converged: bool,
    committed_at_seq: u64,
    by_facet: Vec<SliceView>,
    by_kind: Vec<SliceView>,
    decoy_confirm_rate: f32,
    decoy_sample_size: u32,
    fast_verdict_rate: f32,
    longest_confirm_streak: u32,
    expiry_rate: f32,
}

#[derive(Serialize)]
struct SliceView {
    label: String,
    score: f32,
    sample_size: u32,
    interval: (f32, f32),
}

fn fidelity(engine: &Engine) -> Result<String, Status> {
    use ghostr_core::fidelity::ScoreWindow;

    let score = crate::ops::fidelity(engine, ScoreWindow::Rolling30).map_err(|e| classify(&e))?;
    fn slices<K: core::fmt::Debug>(
        m: &std::collections::BTreeMap<K, ghostr_core::fidelity::FacetScore>,
    ) -> Vec<SliceView> {
        m.iter()
            .map(|(k, v)| SliceView {
                label: format!("{k:?}"),
                score: v.score,
                sample_size: v.sample_size,
                interval: v.confidence_interval,
            })
            .collect()
    }

    encode(&FidelityView {
        overall: score.overall,
        sample_size: score.sample_size,
        interval: score.confidence_interval,
        brier: score.calibration.brier,
        ece: score.calibration.ece,
        converged: score.converged,
        committed_at_seq: score.committed_at_seq,
        by_facet: slices(&score.by_facet),
        by_kind: slices(&score.by_quest_kind),
        decoy_confirm_rate: score.integrity.decoy_confirm_rate,
        decoy_sample_size: score.integrity.decoy_sample_size,
        fast_verdict_rate: score.integrity.fast_verdict_rate,
        longest_confirm_streak: score.integrity.longest_confirm_streak,
        expiry_rate: score.integrity.expiry_rate,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A vault with an adopted persona and a day of quests.
    fn ready(dir: &std::path::Path) -> (Engine, Token, ghostr_testkit::FixedClock) {
        use chrono_tz::Tz;
        use ghostr_core::sensitivity::{Sensitivity, TrustLevel};
        use ghostr_core::time::Timestamp;
        use ghostr_crypto::kdf::Argon2Params;
        use ghostr_crypto::secret::SecretString;
        use ghostr_testkit::{CorpusGenerator, FixedClock, SeededRng};

        let pass = || SecretString::new("correct horse battery staple".to_owned());
        let cheap = Argon2Params {
            memory_kib: 8,
            iterations: 1,
            lanes: 1,
        };
        Engine::init(dir, &pass(), Tz::UTC, None, None, cheap).expect("init");

        let clock = FixedClock::at(Timestamp::new(1_767_571_200_000, 0), Tz::UTC);
        let engine = Engine::open_with(
            dir,
            &pass(),
            Some(Box::new(clock.clone())),
            Some(Box::new(SeededRng::from_seed(7))),
        )
        .expect("open");

        let fixed = FixedClock::at(Timestamp::new(1_767_000_000_000, 0), Tz::UTC);
        let corpus = CorpusGenerator::new(30).generate(&fixed, &SeededRng::from_seed(42));
        let dek = engine.dek().expect("dek");
        let sources: std::collections::BTreeSet<_> =
            corpus.memories.iter().map(|m| m.source_id).collect();
        for (index, source) in sources.iter().enumerate() {
            engine
                .store()
                .upsert_source_with(
                    dek,
                    &ghostr_store::sqlite::NewSourceRow {
                        id: *source,
                        kind_tag: "markdown_vault",
                        config: "{\"location\":\"/synthetic\"}",
                        trust: TrustLevel::FirstParty,
                        sensitivity: Sensitivity::Private,
                    },
                    [u8::try_from(index).unwrap_or(0); 24],
                )
                .expect("source");
        }
        for memory in &corpus.memories {
            engine
                .store()
                .put_memory(dek, memory, engine.nonce())
                .expect("put");
        }
        let start = chrono::NaiveDate::from_ymd_opt(2026, 1, 5).expect("date");
        for day in 0..30 {
            crate::ops::memoria(&engine, start + chrono::Duration::days(day)).expect("seal");
        }
        let candidate = crate::ops::propose_persona(&engine).expect("propose");
        crate::ops::adopt_persona(&engine, &candidate).expect("adopt");

        let token = Token("t".repeat(64));
        (engine, token, clock)
    }

    fn request<'a>(method: Method, path: &str, bearer: Option<&'a str>) -> Request<'a> {
        Request {
            method,
            path: path.to_owned(),
            bearer,
            origin: None,
            host: Some("127.0.0.1:7749"),
            body: b"",
        }
    }

    fn text(bytes: &[u8]) -> String {
        String::from_utf8_lossy(bytes).into_owned()
    }

    #[test]
    fn the_page_is_served_without_a_token() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (engine, token, _clock) = ready(dir.path());
        let out = route(
            &engine,
            &token,
            &request(Method::Get, "/", None),
            "<html>hi</html>",
        );
        let rendered = text(&out);
        assert!(rendered.contains("200 OK"));
        assert!(rendered.contains("<html>hi</html>"));
    }

    /// The page carries no data. Requiring a token to fetch it would mean
    /// putting the token in the URL, where it lands in history and proxy logs.
    #[test]
    fn every_api_path_needs_a_token() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (engine, token, _clock) = ready(dir.path());
        for (method, path) in [
            (Method::Get, "/api/status"),
            (Method::Get, "/api/quests"),
            (Method::Get, "/api/fidelity"),
            (Method::Post, "/api/quests/issue"),
        ] {
            let out = text(&route(&engine, &token, &request(method, path, None), ""));
            assert!(out.contains("401 Unauthorized"), "{path} was reachable");
        }
    }

    #[test]
    fn a_wrong_token_is_refused() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (engine, token, _clock) = ready(dir.path());
        let out = text(&route(
            &engine,
            &token,
            &request(Method::Get, "/api/status", Some(&"x".repeat(64))),
            "",
        ));
        assert!(out.contains("401 Unauthorized"));
    }

    /// A page on another origin must not reach this even holding a token. There
    /// are no CORS headers, so a browser would not surface the body — but a
    /// refusal means a request that *writes* never runs at all.
    #[test]
    fn a_cross_origin_request_is_refused_before_it_runs() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (engine, token, _clock) = ready(dir.path());
        let mut req = request(Method::Post, "/api/quests/issue", Some(token.expose()));
        req.origin = Some("https://evil.example");
        let out = text(&route(&engine, &token, &req, ""));
        assert!(out.contains("403 Forbidden"));
        assert_eq!(
            crate::ops::open_quests(&engine, 10).expect("open").len(),
            0,
            "the write must not have happened"
        );
    }

    #[test]
    fn an_unknown_path_is_a_404() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (engine, token, _clock) = ready(dir.path());
        let out = text(&route(
            &engine,
            &token,
            &request(Method::Get, "/api/secrets", Some(token.expose())),
            "",
        ));
        assert!(out.contains("404 Not Found"));
    }

    /// I6. The list a phone renders must not contain the ghost's answer for any
    /// kind that withholds it — this is the same rule the CLI follows, read from
    /// the same place.
    #[test]
    fn the_quest_list_never_carries_a_withheld_answer() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (engine, token, _clock) = ready(dir.path());
        let date = engine.now().date_in(&chrono_tz::Tz::UTC);
        crate::ops::issue_quests(&engine, date).expect("issue");

        let body = text(&route(
            &engine,
            &token,
            &request(Method::Get, "/api/quests", Some(token.expose())),
            "",
        ));
        let open = crate::ops::open_quests(&engine, 100).expect("open");
        assert!(!open.is_empty(), "nothing issued; the check is vacuous");

        let mut withheld = 0;
        for quest in &open {
            if quest.kind.reveals_answer_upfront() {
                continue;
            }
            withheld += 1;
            assert!(
                !body.contains(quest.kind.committed_answer()),
                "{} leaked its answer over the wire",
                quest.kind.variant_name()
            );
        }
        assert!(withheld > 0, "no withholding kind in the batch");
    }

    /// SPEC Q17. Confidence is only measurable as calibration if it did not
    /// influence the outcome it predicts, so it is not in the list.
    #[test]
    fn the_quest_list_does_not_carry_confidence() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (engine, token, _clock) = ready(dir.path());
        let date = engine.now().date_in(&chrono_tz::Tz::UTC);
        crate::ops::issue_quests(&engine, date).expect("issue");

        let body = text(&route(
            &engine,
            &token,
            &request(Method::Get, "/api/quests", Some(token.expose())),
            "",
        ));
        assert!(!body.contains("confidence"));
        assert!(!body.contains("holdout"), "and not which ones are scored");
        assert!(
            !body.contains("decoy"),
            "and certainly not which are decoys"
        );
    }

    #[test]
    fn a_verdict_records_and_reveals_only_afterwards() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (engine, token, clock) = ready(dir.path());
        let date = engine.now().date_in(&chrono_tz::Tz::UTC);
        crate::ops::issue_quests(&engine, date).expect("issue");
        let quest = crate::ops::open_quests(&engine, 1).expect("open").remove(0);
        clock.advance(30);

        let body = "{\"verdict\":\"confirm\"}";
        let path = format!("/api/quests/{}/answer", quest.id);
        let mut req = request(Method::Post, &path, Some(token.expose()));
        req.body = body.as_bytes();
        let out = text(&route(&engine, &token, &req, ""));

        assert!(out.contains("200 OK"), "{out}");
        assert!(out.contains("ghost_confidence"));
        assert_eq!(
            crate::ops::get_quest(&engine, quest.id)
                .expect("get")
                .status,
            ghostr_core::quest::QuestStatus::Answered
        );
    }

    #[test]
    fn a_second_verdict_is_a_conflict() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (engine, token, clock) = ready(dir.path());
        let date = engine.now().date_in(&chrono_tz::Tz::UTC);
        crate::ops::issue_quests(&engine, date).expect("issue");
        let quest = crate::ops::open_quests(&engine, 1).expect("open").remove(0);
        clock.advance(30);

        let body = "{\"verdict\":\"confirm\"}";
        let path = format!("/api/quests/{}/answer", quest.id);
        let mut req = request(Method::Post, &path, Some(token.expose()));
        req.body = body.as_bytes();
        assert!(text(&route(&engine, &token, &req, "")).contains("200 OK"));
        assert!(text(&route(&engine, &token, &req, "")).contains("409 Conflict"));
    }

    /// A correction with no words would be the ghost putting text in its
    /// owner's mouth.
    #[test]
    fn a_correction_without_words_is_refused() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (engine, token, clock) = ready(dir.path());
        let date = engine.now().date_in(&chrono_tz::Tz::UTC);
        crate::ops::issue_quests(&engine, date).expect("issue");
        let quest = crate::ops::open_quests(&engine, 1).expect("open").remove(0);
        clock.advance(30);

        let path = format!("/api/quests/{}/answer", quest.id);
        for body in [
            "{\"verdict\":\"correct\"}",
            "{\"verdict\":\"correct\",\"text\":\"   \"}",
        ] {
            let mut req = request(Method::Post, &path, Some(token.expose()));
            req.body = body.as_bytes();
            assert!(
                text(&route(&engine, &token, &req, "")).contains("400 Bad Request"),
                "{body}"
            );
        }
    }

    #[test]
    fn a_malformed_body_is_a_bad_request_not_a_crash() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (engine, token, _clock) = ready(dir.path());
        let mut req = request(
            Method::Post,
            "/api/quests/qst:not-a-uuid/answer",
            Some(token.expose()),
        );
        req.body = b"{";
        assert!(text(&route(&engine, &token, &req, "")).contains("400 Bad Request"));
    }

    /// A new vault has nothing to score, and the API says so rather than
    /// returning a number over a handful of quests.
    #[test]
    fn fidelity_without_evidence_is_unprocessable_not_a_number() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (engine, token, _clock) = ready(dir.path());
        let out = text(&route(
            &engine,
            &token,
            &request(Method::Get, "/api/fidelity", Some(token.expose())),
            "",
        ));
        assert!(out.contains("422 Unprocessable"));
        assert!(!out.contains("overall"));
    }

    /// SPEC §3.7. A client that could ask for the bare number would eventually
    /// be written, so there is no shape of this response without the interval,
    /// the sample size, and the integrity signals.
    #[test]
    fn a_score_always_travels_with_what_qualifies_it() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (engine, token, clock) = ready(dir.path());
        let start = chrono::NaiveDate::from_ymd_opt(2026, 1, 5).expect("date");

        for day in 0..30 {
            crate::ops::issue_quests(&engine, start + chrono::Duration::days(day)).expect("issue");
            for quest in crate::ops::open_quests(&engine, 100).expect("open") {
                clock.advance(30);
                crate::ops::answer_quest(&engine, quest.id, ghostr_core::quest::Verdict::Confirm)
                    .expect("answer");
            }
            clock.advance(86_400 - 3_600);
        }

        let out = text(&route(
            &engine,
            &token,
            &request(Method::Get, "/api/fidelity", Some(token.expose())),
            "",
        ));
        assert!(out.contains("200 OK"), "{out}");
        for field in [
            "overall",
            "sample_size",
            "interval",
            "brier",
            "ece",
            "decoy_confirm_rate",
            "fast_verdict_rate",
            "expiry_rate",
            "committed_at_seq",
        ] {
            assert!(out.contains(field), "a score went out without {field}");
        }
    }

    /// Without these an installed copy is a bookmark: iOS falls back to a
    /// screenshot of whatever the page looked like when it was saved, which is
    /// usually a spinner.
    #[test]
    fn the_page_furniture_is_served_without_a_token() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (engine, token, _clock) = ready(dir.path());
        for (path, marker) in [
            ("/manifest.webmanifest", "standalone"),
            ("/icon.svg", "<svg"),
        ] {
            let out = text(&route(
                &engine,
                &token,
                &request(Method::Get, path, None),
                "",
            ));
            assert!(out.contains("200 OK"), "{path}");
            assert!(out.contains(marker), "{path}");
        }

        let png = route(
            &engine,
            &token,
            &request(Method::Get, "/icon.png", None),
            "",
        );
        assert!(text(&png).contains("200 OK"));
        assert!(
            png.windows(4).any(|w| w == b"PNG\x0d" || w == b"\x89PNG"),
            "the icon did not come back as a PNG"
        );
    }

    /// The thing that makes a phone a client rather than a window: a thought
    /// recorded where it happened.
    #[test]
    fn a_journal_entry_is_stored_and_not_echoed_back() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (engine, token, _clock) = ready(dir.path());
        const ENTRY: &str = "the train was late so I read on the platform instead";

        let body = format!("{{\"text\":\"{ENTRY}\"}}");
        let mut req = request(Method::Post, "/api/journal", Some(token.expose()));
        req.body = body.as_bytes();
        let out = text(&route(&engine, &token, &req, ""));

        assert!(out.contains("200 OK"), "{out}");
        // The id comes back, not the words. There is no reason to send a memory
        // back over the socket it just arrived on.
        assert!(!out.contains("platform"), "the entry was echoed back");

        let dek = engine.dek().expect("dek");
        assert!(
            engine
                .store()
                .all_memories(dek)
                .expect("memories")
                .iter()
                .any(|m| m.body.text == ENTRY),
            "the entry was not stored"
        );
    }

    /// I1. It goes straight into the encrypted store — never a plaintext file,
    /// not even a temporary one.
    #[test]
    fn a_journal_entry_never_lands_in_plaintext_on_disk() {
        let dir = tempfile::tempdir().expect("tempdir");
        const ENTRY: &str = "met Nan at the tea shop about the lease";
        {
            let (engine, token, _clock) = ready(dir.path());
            let body = format!("{{\"text\":\"{ENTRY}\"}}");
            let mut req = request(Method::Post, "/api/journal", Some(token.expose()));
            req.body = body.as_bytes();
            assert!(text(&route(&engine, &token, &req, "")).contains("200 OK"));
        }

        let mut raw = Vec::new();
        for entry in std::fs::read_dir(dir.path()).expect("read dir").flatten() {
            raw.extend(std::fs::read(entry.path()).unwrap_or_default());
        }
        assert!(
            !raw.windows(ENTRY.len()).any(|w| w == ENTRY.as_bytes()),
            "a journal entry reached the disk in plaintext"
        );
    }

    #[test]
    fn an_empty_journal_entry_is_refused() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (engine, token, _clock) = ready(dir.path());
        for body in ["{\"text\":\"\"}", "{\"text\":\"   \"}", "{}"] {
            let mut req = request(Method::Post, "/api/journal", Some(token.expose()));
            req.body = body.as_bytes();
            assert!(
                text(&route(&engine, &token, &req, "")).contains("400 Bad Request"),
                "{body}"
            );
        }
    }

    #[test]
    fn the_recap_shows_the_day_without_sealing_it() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (engine, token, _clock) = ready(dir.path());
        let before = engine.store().tip().expect("tip").map_or(0, |t| t.seq);

        let out = text(&route(
            &engine,
            &token,
            &request(Method::Get, "/api/recap", Some(token.expose())),
            "",
        ));
        assert!(out.contains("200 OK"), "{out}");
        assert!(out.contains("highlights"));

        // Looking at today must not close it (I2, I3).
        assert_eq!(
            engine.store().tip().expect("tip").map_or(0, |t| t.seq),
            before,
            "reading the recap advanced the chain"
        );
    }

    /// I8. Status is a dashboard, not a window into the corpus.
    #[test]
    fn status_carries_counts_and_no_content() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (engine, token, _clock) = ready(dir.path());
        let out = text(&route(
            &engine,
            &token,
            &request(Method::Get, "/api/status", Some(token.expose())),
            "",
        ));
        assert!(out.contains("sealed_days"));
        assert!(out.contains("npub1"));

        // Nothing from the corpus. Every memory body is checked rather than a
        // sample, because the one that leaks is never the one you spot-check.
        let dek = engine.dek().expect("dek");
        for memory in engine.store().all_memories(dek).expect("memories") {
            let words: Vec<&str> = memory.body.text.split_whitespace().take(6).collect();
            if words.len() >= 6 {
                assert!(!out.contains(&words.join(" ")), "status leaked corpus text");
            }
        }
    }
}
