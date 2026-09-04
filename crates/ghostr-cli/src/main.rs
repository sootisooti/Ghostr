//! `ghostr` — the Ghostr command-line interface.
//!
//! A thin shell over [`ghostr_engine`]. It parses arguments, calls the engine,
//! and renders. `anyhow` is used here and only here (with `xtask`), because a
//! binary wants a chain of context and a library wants a matchable enum.
//!
//! # M0 is offline
//!
//! Every command except `anchor` runs with no network at all, and `anchor`
//! degrades to a recorded failure rather than blocking anything.

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]
// `print_stdout` is denied workspace-wide to keep memory content out of process
// output by accident. This binary's whole job is writing to stdout, so it is
// allowed here and rendering stays confined to `render`.
#![allow(clippy::print_stdout, clippy::print_stderr)]

mod render;

use std::path::PathBuf;

use anyhow::{Context as _, Result, bail};
use clap::{Parser, Subcommand};
use ghostr_crypto::secret::SecretString;
use ghostr_engine::config::Config;
use ghostr_engine::engine::Engine;
use ghostr_engine::ops;

/// A digital ghost: an agent that clones your identity, verified daily.
#[derive(Debug, Parser)]
#[command(name = "ghostr", version, about, long_about = None)]
struct Cli {
    /// Vault directory. Defaults to `$GHOSTR_HOME`, else `$XDG_DATA_HOME/ghostr`.
    #[arg(long, global = true)]
    home: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Generate a nostr keypair and create an encrypted vault.
    Init {
        /// Import an existing BIP-39 mnemonic instead of generating one.
        #[arg(long)]
        import: bool,
        /// Use an existing nostr `nsec` as this vault's identity.
        ///
        /// The vault still generates its own seed for the ghost, anchor and
        /// data keys — an `nsec` is a raw key with no derivation tree under it
        /// — so there are two things to back up, not one (SPEC §14 Q21).
        #[arg(long)]
        nsec: bool,
        /// Home timezone, which decides where day boundaries fall.
        #[arg(long, default_value = "UTC")]
        tz: String,
    },

    /// Ingest a folder of markdown notes.
    Ingest {
        /// The folder to read.
        path: PathBuf,
    },

    /// Compile and seal a day's footage.
    Memoria {
        /// Which day: `today`, `yesterday`, or `YYYY-MM-DD`.
        #[arg(long, default_value = "today")]
        date: String,
        /// Show what would be sent to a remote model, and send nothing.
        ///
        /// Requires `--remote`. There is no dry run of the local path because
        /// nothing leaves the device on it, and nothing is what a dry run is
        /// for.
        #[arg(long)]
        dry_run: bool,
        /// Route summarisation at the configured remote provider.
        #[arg(long)]
        remote: bool,
    },

    /// Show a day, sealing nothing.
    Recap {
        /// Which day: `today`, `yesterday`, or `YYYY-MM-DD`.
        #[arg(default_value = "today")]
        date: String,
    },

    /// Configured sources.
    #[command(subcommand)]
    Source(SourceCommand),

    /// Threads still open at the chain tip.
    #[command(subcommand)]
    Thread(ThreadCommand),

    /// Entries made inside Ghostr.
    #[command(subcommand)]
    Journal(JournalCommand),

    /// What has left this device.
    #[command(subcommand)]
    Egress(EgressCommand),

    /// The ghost's model of you.
    #[command(subcommand)]
    Persona(PersonaCommand),

    /// Inspect sealed footage.
    #[command(subcommand)]
    Footage(FootageCommand),

    /// The daily verification loop.
    #[command(subcommand)]
    Quest(QuestCommand),

    /// How well the ghost matches you, and what qualifies the number.
    Fidelity {
        /// The window: `30`, `90`, or `all`.
        #[arg(long, default_value = "30")]
        window: String,
    },

    /// Submit the chain tip to OpenTimestamps. The only networked command.
    Anchor,

    /// Serve the local API, and the page that drives the daily loop.
    Serve {
        /// Also listen on TCP, so a browser can reach it.
        ///
        /// Takes an address. `--http` alone means loopback on the default port,
        /// which only this machine can reach.
        #[arg(long, num_args = 0..=1, default_missing_value = "127.0.0.1:7749")]
        http: Option<String>,

        /// Acknowledge that a non-loopback bind puts the vault on a network.
        ///
        /// Required for any address other than loopback. Deliberately a second
        /// flag: `--http 0.0.0.0:7749` is one typo away from `--http
        /// 127.0.0.1:7749`, and the difference is who can read your journal.
        #[arg(long)]
        lan: bool,
    },

    /// Re-derive the chain from genesis and check every link.
    Verify,

    /// Show vault status.
    Status,

    /// Publish sealed footage to the configured relays, encrypted.
    ///
    /// A backup, not a broadcast: every day is encrypted to this vault's own
    /// data key, so a relay stores something only this vault can read.
    Sync,

    /// Rebuild this vault's history from relays.
    ///
    /// For a machine that has the seed and nothing else. The result is a
    /// *replica*: it holds the history and does not seal, because the machine
    /// that has been sealing still is (SPEC §14 Q10).
    Restore,

    /// Change the passphrase that unlocks this vault.
    ///
    /// Cheap: the journal is encrypted under a key the passphrase does not
    /// touch, so this rewraps the seed rather than re-encrypting the corpus.
    Passphrase,
}

#[derive(Debug, Subcommand)]
enum SourceCommand {
    /// Add a source, after showing what adding it means.
    Add {
        /// Which adapter: `markdown`, `journal`, `structlog`, or `nostr`.
        kind: String,
        /// Path it reads from. Omitted for `journal` and `nostr`, which have none.
        #[arg(default_value = "")]
        path: String,
        /// For `structlog`, which schema its rows conform to:
        /// `places`, `people`, `habits`, `health`, or `media`.
        #[arg(long)]
        schema: Option<String>,
        /// For `nostr`, whose feed: an `npub1...` or a 64-character hex pubkey.
        #[arg(long)]
        pubkey: Option<String>,
        /// For `nostr`, a relay to read from. Repeat for more than one.
        ///
        /// Named per feed rather than taken from the vault's relay list: where
        /// a backup goes and where somebody else's notes come from are two
        /// different decisions.
        #[arg(long = "relay")]
        relays: Vec<String>,
        /// For `nostr`, which event kinds to read: `1` (short notes) and
        /// `30023` (long-form). Both, by default.
        #[arg(long = "kind-filter")]
        kind_filters: Vec<u16>,
    },
    /// List configured sources.
    List,
    /// Pull from every enabled source.
    Sync {
        /// Only this source, by its full or short id.
        #[arg(long)]
        id: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
enum ThreadCommand {
    /// Threads still open.
    List,
}

#[derive(Debug, Subcommand)]
enum JournalCommand {
    /// Record an entry. It goes straight into the encrypted vault.
    Add {
        /// The entry. Read from stdin when omitted.
        text: Option<String>,
    },
    /// Import a running journal file, split at its timestamp headings.
    Import {
        /// The file, or a directory of them.
        path: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum PersonaCommand {
    /// Show the current model.
    Show,
    /// Propose a new version, without adopting it.
    Distill {
        /// Adopt it immediately instead of only proposing it.
        ///
        /// Off by default: reading the diff first is the point of the two
        /// steps, and a substantial change should not take effect because
        /// nobody looked.
        #[arg(long)]
        adopt: bool,
    },
    /// Adopt the version a `distill` proposed.
    Adopt,
    /// What changed between two versions.
    Diff {
        /// The older version's ordinal.
        from: u32,
        /// The newer version's ordinal.
        to: u32,
    },
    /// Every version, newest first.
    History {
        /// How many to show.
        #[arg(long, default_value_t = 20)]
        limit: u32,
    },
}

#[derive(Debug, Subcommand)]
enum QuestCommand {
    /// Generate a day's quests, committing to every answer first.
    Issue {
        /// Which day: `today`, `yesterday`, or `YYYY-MM-DD`.
        #[arg(default_value = "today")]
        date: String,
    },
    /// Quests awaiting your verdict.
    List {
        /// How many to show.
        #[arg(long, default_value_t = 10)]
        limit: u32,
    },
    /// One quest in full.
    Show {
        /// The quest, by its full or short id.
        id: String,
    },
    /// Answer a quest.
    Answer {
        /// The quest, by its full or short id.
        id: String,
        /// `confirm`, `correct`, `reject`, `unknown`, or `void`.
        verdict: String,
        /// The correction, the rejection note, or the reason it was broken.
        ///
        /// Required by `correct` and `void`, optional for `reject`, and
        /// meaningless to the rest.
        #[arg(long)]
        text: Option<String>,
        /// For `correct`: how far off the ghost was — `minor` or `major`.
        #[arg(long, default_value = "minor")]
        severity: String,
    },
}

#[derive(Debug, Subcommand)]
enum EgressCommand {
    /// Every decision the gate made, newest first.
    Log {
        /// Only the last N days.
        #[arg(long)]
        days: Option<u32>,
    },
}

#[derive(Debug, Subcommand)]
enum FootageCommand {
    /// List sealed days.
    List,
    /// Show one day in full.
    Show {
        /// The sequence number, as shown by `footage list`.
        id: u64,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    if let Err(e) = run(cli) {
        // `{:#}` prints the whole context chain, which is the reason anyhow is
        // here: "could not seal: chain gap: expected 4, got 6" beats any one of
        // those lines alone.
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }
    Ok(())
}

fn run(cli: Cli) -> Result<()> {
    let dir = cli.home.unwrap_or_else(Config::default_dir);

    match cli.command {
        Command::Init { import, nsec, tz } => cmd_init(&dir, import, nsec, &tz),
        Command::Passphrase => cmd_passphrase(&dir),
        Command::Sync => cmd_sync(&dir),
        Command::Restore => cmd_restore(&dir),
        Command::Ingest { path } => cmd_ingest(&dir, &path),
        Command::Memoria {
            date,
            dry_run,
            remote,
        } => cmd_memoria(&dir, &date, dry_run, remote),
        Command::Recap { date } => cmd_recap(&dir, &date),
        Command::Source(SourceCommand::Add {
            kind,
            path,
            schema,
            pubkey,
            relays,
            kind_filters,
        }) => cmd_source_add(
            &dir,
            &kind,
            &path,
            schema.as_deref(),
            pubkey.as_deref(),
            &relays,
            &kind_filters,
        ),
        Command::Source(SourceCommand::List) => cmd_source_list(&dir),
        Command::Source(SourceCommand::Sync { id }) => cmd_source_sync(&dir, id.as_deref()),
        Command::Thread(ThreadCommand::List) => cmd_thread_list(&dir),
        Command::Journal(JournalCommand::Add { text }) => cmd_journal_add(&dir, text.as_deref()),
        Command::Journal(JournalCommand::Import { path }) => cmd_journal_import(&dir, &path),
        Command::Egress(EgressCommand::Log { days }) => cmd_egress_log(&dir, days),
        Command::Persona(PersonaCommand::Show) => cmd_persona_show(&dir),
        Command::Persona(PersonaCommand::Distill { adopt }) => cmd_persona_distill(&dir, adopt),
        Command::Persona(PersonaCommand::Adopt) => cmd_persona_adopt(&dir),
        Command::Persona(PersonaCommand::Diff { from, to }) => cmd_persona_diff(&dir, from, to),
        Command::Persona(PersonaCommand::History { limit }) => cmd_persona_history(&dir, limit),
        Command::Quest(QuestCommand::Issue { date }) => cmd_quest_issue(&dir, &date),
        Command::Quest(QuestCommand::List { limit }) => cmd_quest_list(&dir, limit),
        Command::Quest(QuestCommand::Show { id }) => cmd_quest_show(&dir, &id),
        Command::Quest(QuestCommand::Answer {
            id,
            verdict,
            text,
            severity,
        }) => cmd_quest_answer(&dir, &id, &verdict, text.as_deref(), &severity),
        Command::Fidelity { window } => cmd_fidelity(&dir, &window),
        Command::Footage(FootageCommand::List) => cmd_footage_list(&dir),
        Command::Footage(FootageCommand::Show { id }) => cmd_footage_show(&dir, id),
        Command::Anchor => cmd_anchor(&dir),
        Command::Serve { http, lan } => cmd_serve(&dir, http.as_deref(), lan),
        Command::Verify => cmd_verify(&dir),
        Command::Status => cmd_status(&dir),
    }
}

/// Reads the passphrase.
///
/// `GHOSTR_PASSPHRASE` exists so the integration test and scripts can drive the
/// CLI without a TTY. It is deliberately *not* the documented path for humans:
/// an environment variable is visible to every process in the session and lands
/// in shell history.
fn passphrase(confirm: bool) -> Result<SecretString> {
    if let Ok(from_env) = std::env::var("GHOSTR_PASSPHRASE") {
        return Ok(SecretString::new(from_env));
    }
    let entered = rpassword_prompt("passphrase: ")?;
    if confirm {
        let again = rpassword_prompt("passphrase (again): ")?;
        if entered != again {
            bail!("passphrases do not match");
        }
    }
    Ok(SecretString::new(entered))
}

/// Reads a line without echoing it.
///
/// Hand-rolled rather than pulling `rpassword`: on Unix this is one `stty`
/// call, and the dependency budget is better spent elsewhere
/// (THREAT_MODEL §T8). On other platforms it falls back to an echoing read and
/// says so, rather than pretending the input was hidden.
fn rpassword_prompt(prompt: &str) -> Result<String> {
    use std::io::{BufRead as _, Write as _};

    eprint!("{prompt}");
    std::io::stderr().flush().ok();

    #[cfg(unix)]
    let restore = {
        let hidden = std::process::Command::new("stty")
            .args(["-echo"])
            .stdin(std::process::Stdio::inherit())
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if !hidden {
            eprintln!("\n(warning: could not disable echo; your passphrase will be visible)");
        }
        hidden
    };
    #[cfg(not(unix))]
    let restore = {
        eprintln!("\n(warning: echo suppression is unavailable on this platform)");
        false
    };

    let mut line = String::new();
    let read = std::io::stdin().lock().read_line(&mut line);

    #[cfg(unix)]
    if restore {
        let _ = std::process::Command::new("stty").args(["echo"]).status();
        eprintln!();
    }
    #[cfg(not(unix))]
    let _ = restore;

    read.context("reading passphrase")?;
    Ok(line.trim_end_matches(['\r', '\n']).to_owned())
}

fn cmd_init(dir: &std::path::Path, import: bool, nsec: bool, tz: &str) -> Result<()> {
    let home_tz = tz
        .parse()
        .map_err(|_| anyhow::anyhow!("`{tz}` is not an IANA timezone"))?;

    let imported = if import {
        let phrase = rpassword_prompt("mnemonic: ")?;
        Some(SecretString::new(phrase))
    } else {
        None
    };
    // Read with echo off, like a passphrase. An `nsec` is a private key, and a
    // key left on screen is a key in a screenshot, a scrollback, and a recording.
    let brought = if nsec {
        eprintln!(
            "\n  Pasting an nsec makes it this vault's identity.\n  \
             The vault still generates its own seed for everything else,\n  \
             so you will have TWO things to back up: this key and that seed.\n"
        );
        Some(SecretString::new(rpassword_prompt("nsec: ")?))
    } else {
        None
    };
    let pass = passphrase(true)?;

    let (engine, outcome) = Engine::init(
        dir,
        &pass,
        home_tz,
        imported,
        brought,
        ghostr_crypto::kdf::Argon2Params::recommended(),
    )
    .context("creating the vault")?;

    println!("{}", render::init(&engine, &outcome, dir));
    Ok(())
}

/// Fills a buffer with OS randomness.
///
/// The composition root is the only place this happens (SPEC §11.4); every
/// crate below takes the bytes it needs as an argument.
fn fill_random(buf: &mut [u8]) {
    use ghostr_core::time::Rng as _;
    ghostr_engine::runtime::OsRng.fill(buf);
}

/// Builds a relay client from the vault's config.
///
/// Refuses rather than defaulting to a relay list of our choosing: which relays
/// a vault talks to is the user's decision, and picking one for them would put
/// their encrypted history somewhere they never named.
fn relay_client(engine: &Engine) -> Result<ghostr_nostr::client::websocket::WebsocketRelayClient> {
    let config = engine.config()?;
    if config.relays.is_empty() {
        anyhow::bail!("no relays configured — add them to config.toml as `relays = [\"wss://…\"]`");
    }
    Ok(ghostr_nostr::client::websocket::WebsocketRelayClient::new(
        config.relays.clone(),
        config.enabled_scopes(),
    ))
}

/// Publishes sealed footage to relays.
fn cmd_sync(dir: &std::path::Path) -> Result<()> {
    let engine = open(dir)?;
    let relays = relay_client(&engine)?;
    let report =
        block_on(ghostr_engine::sync::sync(&engine, &relays)).context("syncing to relays")?;

    println!("published      {}", report.published);
    println!("mirrored       {}", report.mirrored);
    println!("already there  {}", report.already_present);
    if !report.failed.is_empty() {
        // Named rather than counted: a day that failed is a day the user may
        // want to retry, and "3 failed" does not say which.
        println!("failed         {:?}", report.failed);
    }
    if !report.mirror_failed.is_empty() {
        // The day is backed up; its fallback is not. Worth saying, because a
        // vault without the mirror depends on kinds 31780–31789 resolving —
        // the assumption the mirror exists to remove (SPEC Q3).
        println!("no mirror      {:?}", report.mirror_failed);
    }
    Ok(())
}

/// Rebuilds history from relays.
fn cmd_restore(dir: &std::path::Path) -> Result<()> {
    let engine = open(dir)?;
    let relays = relay_client(&engine)?;
    let report = block_on(ghostr_engine::sync::restore(&engine, &relays))
        .context("restoring from relays")?;

    println!("recovered  {} day(s)", report.recovered);
    if let Some(tip) = report.tip {
        println!("tip        seq {tip}");
    }
    if report.rejected > 0 {
        println!(
            "ignored    {} event(s) this vault could not read",
            report.rejected
        );
    }
    println!();
    println!("  this device is now a replica: it holds the history and does not seal.");
    println!("  exactly one device per chain advances `seq`, and a second one would fork it.");
    Ok(())
}

/// Drives one async call to completion.
///
/// The composition root owns the runtime, as it does for the model path. `rt`
/// only — every I/O path underneath is blocking, so there is no reactor to
/// enable.
fn block_on<F: std::future::Future>(future: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .map(|rt| rt.block_on(future))
        .unwrap_or_else(|_| unreachable!("a current-thread runtime cannot fail to build"))
}

/// Changes the passphrase, asking for the old one first.
///
/// The old passphrase is not a formality: a rewrap needs the plaintext seed,
/// which is only reachable by unwrapping with it (SPEC §14 Q19). Asking for it
/// is also what stops someone at an unlocked laptop from re-keying the vault.
fn cmd_passphrase(dir: &std::path::Path) -> Result<()> {
    let old = SecretString::new(rpassword_prompt("current passphrase: ")?);
    let mut engine = Engine::open(dir, &old).context("opening the vault")?;

    eprintln!(
        "\n  This changes only what unlocks the vault. Your recovery phrase is\n  \
         unchanged, and so is everything already written down.\n"
    );
    let new = passphrase(true)?;

    // Entropy drawn here, in the composition root, and nowhere deeper.
    let mut salt = [0u8; 16];
    let mut seed_nonce = [0u8; 24];
    let mut identity_nonce = [0u8; 24];
    fill_random(&mut salt);
    fill_random(&mut seed_nonce);
    fill_random(&mut identity_nonce);
    let entropy = ghostr_crypto::keystore::WrapEntropy::new(salt, seed_nonce, identity_nonce)
        .context("drawing entropy for the rewrap")?;

    engine
        .change_passphrase(old, new, entropy)
        .context("changing the passphrase")?;
    println!("passphrase changed");
    println!("  the old one no longer opens this vault");
    Ok(())
}

fn cmd_ingest(dir: &std::path::Path, path: &std::path::Path) -> Result<()> {
    let engine = open(dir)?;
    let report = ops::ingest(&engine, path).context("ingesting notes")?;
    println!("{}", render::ingest(&report, path));
    Ok(())
}

fn cmd_memoria(dir: &std::path::Path, date: &str, dry_run: bool, remote: bool) -> Result<()> {
    let engine = open(dir)?;
    let day = engine.resolve_date(date)?;

    if dry_run {
        if !remote {
            bail!(
                "--dry-run needs --remote: nothing leaves the device on the local path, \
                 so there is nothing to preview"
            );
        }
        return cmd_dry_run_remote(&engine, day);
    }
    if remote {
        bail!(
            "routing memoria at a remote provider is not implemented yet; \
             `--dry-run --remote` shows what it would send"
        );
    }

    let outcome = ops::memoria(&engine, day).context("compiling footage")?;
    let footage = &outcome.footage;
    println!("{}", render::sealed(footage));
    if outcome.dropped_claims > 0 {
        // Said out loud. A recap that quietly got shorter is one the user
        // cannot tell from a day that had less to say.
        println!(
            "  {} claim(s) dropped for want of evidence",
            outcome.dropped_claims
        );
    }
    Ok(())
}

fn cmd_quest_issue(dir: &std::path::Path, date: &str) -> Result<()> {
    let engine = open(dir)?;
    let day = engine.resolve_date(date)?;
    let issue = ops::issue_quests(&engine, day).context("issuing quests")?;
    println!("{}", render::quest_issue(&issue));
    Ok(())
}

fn cmd_quest_list(dir: &std::path::Path, limit: u32) -> Result<()> {
    let engine = open(dir)?;
    let quests = ops::open_quests(&engine, limit).context("reading open quests")?;
    println!("{}", render::quest_list(&quests));
    Ok(())
}

fn cmd_quest_show(dir: &std::path::Path, id: &str) -> Result<()> {
    let engine = open(dir)?;
    let quest = ops::find_quest(&engine, id).context("reading the quest")?;
    println!("{}", render::quest_show(&quest));
    Ok(())
}

fn cmd_quest_answer(
    dir: &std::path::Path,
    id: &str,
    verdict: &str,
    text: Option<&str>,
    severity: &str,
) -> Result<()> {
    // Parsed before the vault is opened: a typo in the verdict is the user's to
    // fix, and making them wait through a key derivation to hear about it is
    // rude.
    let parsed = parse_verdict(verdict, text, severity)?;
    let engine = open(dir)?;
    let quest = ops::find_quest(&engine, id).context("reading the quest")?;
    let outcome = ops::answer_quest(&engine, quest.id, parsed).context("recording the verdict")?;
    println!("{}", render::quest_answered(&quest, &outcome));
    Ok(())
}

/// Turns the CLI's words into a [`Verdict`](ghostr_core::quest::Verdict).
///
/// `correct` and `void` refuse to proceed without their text rather than
/// substituting an empty string: a correction with no words is the ghost
/// putting text in its owner's mouth, and a void with no reason cannot be
/// reviewed later.
fn parse_verdict(
    verdict: &str,
    text: Option<&str>,
    severity: &str,
) -> Result<ghostr_core::quest::Verdict> {
    use ghostr_core::quest::{Severity, Verdict};

    let words = |what: &str| -> Result<String> {
        match text.map(str::trim).filter(|t| !t.is_empty()) {
            Some(t) => Ok(t.to_owned()),
            None => bail!("`{what}` needs --text"),
        }
    };

    Ok(match verdict.trim().to_lowercase().as_str() {
        "confirm" | "yes" => Verdict::Confirm,
        "correct" => Verdict::Correct {
            correction: words("correct")?,
            severity: match severity.trim().to_lowercase().as_str() {
                "major" => Severity::Major,
                "minor" => Severity::Minor,
                other => bail!("`{other}` is not a severity; try `minor` or `major`"),
            },
        },
        "reject" | "no" => Verdict::Reject {
            note: text
                .map(str::trim)
                .filter(|t| !t.is_empty())
                .map(str::to_owned),
        },
        "unknown" | "dunno" => Verdict::Unknown,
        "void" | "broken" => Verdict::Void {
            reason: words("void")?,
        },
        other => {
            bail!("`{other}` is not a verdict; try confirm, correct, reject, unknown, or void")
        }
    })
}

fn cmd_fidelity(dir: &std::path::Path, window: &str) -> Result<()> {
    use ghostr_core::fidelity::ScoreWindow;

    let engine = open(dir)?;
    let window = match window.trim().to_lowercase().as_str() {
        "30" | "30d" => ScoreWindow::Rolling30,
        "90" | "90d" => ScoreWindow::Rolling90,
        "all" | "alltime" => ScoreWindow::AllTime,
        other => bail!("`{other}` is not a window; try `30`, `90`, or `all`"),
    };

    match ops::fidelity(&engine, window) {
        Ok(score) => println!("{}", render::fidelity(&score)),
        // Not an error the user did anything wrong to cause. A new vault has
        // nothing to score yet, and saying so beats a stack of context.
        Err(ghostr_engine::Error::Quests(ghostr_quests::Error::InsufficientSample {
            have,
            need,
        })) => println!(
            "not enough evidence yet: {have} scored quest(s), need {need}
               answer today's with `ghostr quest list`"
        ),
        Err(e) => return Err(anyhow::Error::new(e).context("scoring")),
    }
    Ok(())
}

fn cmd_footage_list(dir: &std::path::Path) -> Result<()> {
    let engine = open(dir)?;
    let all = engine.store().all_footage(engine.dek()?)?;
    let mut anchors = Vec::new();
    for f in &all {
        anchors.push(engine.store().get_anchor(f.seq)?);
    }
    println!("{}", render::footage_list(&all, &anchors));
    Ok(())
}

fn cmd_footage_show(dir: &std::path::Path, seq: u64) -> Result<()> {
    let engine = open(dir)?;
    let footage = engine
        .store()
        .get_footage(engine.dek()?, seq)?
        .ok_or_else(|| anyhow::anyhow!("no footage with sequence {seq}"))?;
    println!("{}", render::footage_show(&footage));
    Ok(())
}

fn cmd_anchor(dir: &std::path::Path) -> Result<()> {
    let engine = open(dir)?;
    let config = Config::load(dir)?;
    let client = ghostr_anchor::OtsClient::new(
        config
            .calendars
            .iter()
            .map(|url| ghostr_anchor::CalendarConfig { url: url.clone() })
            .collect(),
        std::time::Duration::from_secs(15),
    );
    let record = ops::anchor(&engine, &client).context("anchoring the chain tip")?;
    println!("{}", render::anchor(&record));
    Ok(())
}

/// Serves the local API until interrupted.
///
/// The Unix socket is always bound; TCP is opt-in and a non-loopback bind needs
/// a second flag. That ordering is the documented one (ARCHITECTURE §5): the
/// local API is a socket, and a listener on a port is the exception a user asks
/// for rather than the default they inherit.
fn cmd_serve(dir: &std::path::Path, http: Option<&str>, lan: bool) -> Result<()> {
    use ghostr_engine::serve::{self, Bind, Token};

    let addr = match http {
        Some(spec) => Some(resolve_addr(spec)?),
        None => None,
    };

    if let Some(addr) = addr
        && !serve::is_loopback(&addr)
        && !lan
    {
        bail!(
            "{addr} is reachable from the network, not just this machine.
               Everything the page shows — your memories, your quests, your score —              would be readable by anyone who can reach that address and guess a token.
               Pass --lan as well if that is what you meant."
        );
    }

    let engine = open(dir)?;
    let token = Token::mint(&engine);
    let bind = Bind {
        http: addr,
        lan_acknowledged: lan,
    };

    println!("{}", render::serve_banner(dir, &bind, &token)?);
    serve::serve(engine, &bind, &token).context("serving")
}

/// Parses a bind address, allowing a bare port or a bare host.
fn resolve_addr(spec: &str) -> Result<std::net::SocketAddr> {
    use ghostr_engine::serve::DEFAULT_PORT;

    let spec = spec.trim();
    if let Ok(addr) = spec.parse::<std::net::SocketAddr>() {
        return Ok(addr);
    }
    if let Ok(port) = spec.parse::<u16>() {
        return Ok(std::net::SocketAddr::from(([127, 0, 0, 1], port)));
    }
    if let Ok(ip) = spec.parse::<std::net::IpAddr>() {
        return Ok(std::net::SocketAddr::new(ip, DEFAULT_PORT));
    }
    bail!("`{spec}` is not an address; try `127.0.0.1:7749`, a bare port, or a bare address")
}

fn cmd_verify(dir: &std::path::Path) -> Result<()> {
    let engine = open(dir)?;
    let report = ops::verify(&engine).context("verifying the chain")?;
    println!("{}", render::verify(&report));
    // A broken chain must exit non-zero: `ghostr verify && deploy` has to fail.
    if !report.chain_ok || !report.roots_ok {
        std::process::exit(2);
    }
    Ok(())
}

fn cmd_status(dir: &std::path::Path) -> Result<()> {
    let engine = open(dir)?;
    println!("{}", render::status(&engine)?);
    Ok(())
}

fn open(dir: &std::path::Path) -> Result<Engine> {
    let pass = passphrase(false)?;
    Engine::open(dir, &pass).context("opening the vault")
}

/// Shows what a remote model would receive, and sends nothing.
#[cfg(feature = "llm-remote")]
fn cmd_dry_run_remote(
    engine: &ghostr_engine::engine::Engine,
    day: chrono::NaiveDate,
) -> Result<()> {
    use ghostr_llm::egress::EgressDecision;

    let config = ghostr_llm::gate::RemoteModelConfig {
        provider: std::env::var("GHOSTR_PROVIDER").unwrap_or_else(|_| "anthropic".to_owned()),
        model: std::env::var("GHOSTR_MODEL").unwrap_or_else(|_| "claude-opus-5".to_owned()),
        enabled_tasks: vec![ghostr_llm::model::TaskKind::Summarization],
    };
    let run = ops::dry_run_remote(engine, day, config).context("planning the dry run")?;

    println!("dry run for {} — nothing was sent", run.date);
    println!("  {} memory(ies) in the window", run.memories);
    if run.secret_withheld > 0 {
        println!(
            "  {} withheld as Secret (never offered to the gate at all)",
            run.secret_withheld
        );
    }
    for (index, note) in run.notes.iter().enumerate() {
        match &note.decision {
            EgressDecision::Deny { reason } => {
                println!("\n  [{index}] DENIED: {reason}");
            }
            EgressDecision::Allow | EgressDecision::AllowRedacted(_) => {
                println!(
                    "\n  [{index}] would send {} byte(s), {} name(s) pseudonymised",
                    note.payload.as_ref().map_or(0, String::len),
                    note.entities_pseudonymised
                );
                if let Some(payload) = &note.payload {
                    // The exact bytes, because that is the question the user
                    // asked. Redaction has already happened, so this is what
                    // would leave and not what was in the corpus.
                    for line in payload.lines() {
                        println!("      {line}");
                    }
                }
            }
        }
    }
    Ok(())
}

/// Without a remote provider compiled in there is nothing to preview.
#[cfg(not(feature = "llm-remote"))]
fn cmd_dry_run_remote(
    _engine: &ghostr_engine::engine::Engine,
    _day: chrono::NaiveDate,
) -> Result<()> {
    bail!(
        "this build has no remote provider compiled in, so nothing can leave it; \
         rebuild with `--features llm-remote` if you want one"
    )
}

fn cmd_recap(dir: &std::path::Path, date: &str) -> Result<()> {
    let engine = open(dir)?;
    let day = engine.resolve_date(date)?;
    let recap = ops::recap(&engine, day).context("reading the recap")?;
    println!("{}", render::recap(&recap));
    Ok(())
}

/// Turns what a user pasted into the hex pubkey a filter needs.
///
/// Accepts either form because both are what a nostr client puts on screen: an
/// `npub` is what a profile page shows, hex is what a developer copies out of a
/// relay. Refusing one of them would mean the user has to go and convert it.
fn feed_pubkey(raw: &str) -> Result<String> {
    if raw.starts_with("npub1") {
        let npub = ghostr_core::identity::Npub::parse(raw.to_owned())
            .map_err(|_| anyhow::anyhow!("`{raw}` is not a valid npub"))?;
        let key = ghostr_crypto::nip19::decode_npub(&npub)
            .map_err(|_| anyhow::anyhow!("`{raw}` is not a valid npub"))?;
        return Ok(key.to_hex());
    }
    // Checked here as well as in the engine, so a typo gets a sentence a person
    // can act on rather than the adapter's own "unparseable data at pubkey".
    if raw.len() != 64 || !raw.bytes().all(|b| b.is_ascii_hexdigit()) {
        bail!("`{raw}` is not a pubkey — expected an npub1… or 64 hex characters");
    }
    Ok(raw.to_owned())
}

fn cmd_source_add(
    dir: &std::path::Path,
    kind: &str,
    path: &str,
    schema: Option<&str>,
    pubkey: Option<&str>,
    relays: &[String],
    kind_filters: &[u16],
) -> Result<()> {
    use ghostr_core::source::{LogSchema, SourceKindTag};
    use ghostr_engine::sources::{self, FeedConfig, NewSource};

    let kind = match kind {
        "markdown" | "markdown_vault" => SourceKindTag::MarkdownVault,
        "journal" => SourceKindTag::Journal,
        "structlog" | "structured_log" => SourceKindTag::StructuredLog,
        "nostr" | "nostr_feed" => SourceKindTag::NostrFeed,
        other => {
            bail!("unknown source kind `{other}` (try markdown, journal, structlog, or nostr)")
        }
    };

    let feed = if kind == SourceKindTag::NostrFeed {
        let Some(pubkey) = pubkey else {
            bail!("a nostr feed needs --pubkey (an npub or a hex pubkey)");
        };
        if relays.is_empty() {
            bail!("a nostr feed needs at least one --relay");
        }
        Some(FeedConfig {
            pubkey: feed_pubkey(pubkey)?,
            relays: relays.to_vec(),
            kinds: if kind_filters.is_empty() {
                ghostr_ingest::nostr::READABLE_KINDS.to_vec()
            } else {
                kind_filters.to_vec()
            },
        })
    } else {
        None
    };
    let schema = match schema {
        Some("places") => Some(LogSchema::Places),
        Some("people") => Some(LogSchema::People),
        Some("habits") => Some(LogSchema::Habits),
        Some("health") => Some(LogSchema::Health),
        Some("media") => Some(LogSchema::Media),
        Some(other) => bail!("unknown schema `{other}`"),
        None => None,
    };

    let engine = open(dir)?;
    let (id, plan) = sources::add(
        &engine,
        &NewSource {
            kind,
            location: path.to_owned(),
            schema,
            feed,
        },
    )
    .context("adding the source")?;
    println!("{}", render::source_added(id, &plan));
    Ok(())
}

fn cmd_source_list(dir: &std::path::Path) -> Result<()> {
    let engine = open(dir)?;
    let sources = ghostr_engine::sources::list(&engine).context("listing sources")?;
    println!("{}", render::source_list(&sources));
    Ok(())
}

fn cmd_source_sync(dir: &std::path::Path, id: Option<&str>) -> Result<()> {
    let engine = open(dir)?;
    let only = match id {
        Some(raw) => Some(
            ghostr_core::ids::SourceId::parse(raw)
                .map_err(|_| anyhow::anyhow!("`{raw}` is not a source id"))?,
        ),
        None => None,
    };
    // Built from the feeds' own relays, and only when a feed is configured. Two
    // things follow, both deliberate.
    //
    // A vault of local sources needs no relay list to run `source sync`, so an
    // offline command never asks for the network.
    //
    // And the list is the feeds' own, never the vault's `relays` config — that
    // one is where encrypted backup is published, and reaching for it here
    // would mean adding a feed had quietly widened where the user's history
    // goes. The client is built with no publish scopes at all, so this one
    // cannot publish even if something later asked it to.
    let read_relays = ghostr_engine::sources::feed_relays(&engine).context("reading feeds")?;
    let relays: Option<std::sync::Arc<dyn ghostr_nostr::RelayClient>> = if read_relays.is_empty() {
        None
    } else {
        Some(std::sync::Arc::new(
            ghostr_nostr::client::websocket::WebsocketRelayClient::new(
                read_relays,
                std::collections::HashSet::new(),
            ),
        ))
    };

    let report = block_on(ghostr_engine::sources::sync(&engine, only, relays.as_ref()))
        .context("syncing")?;
    println!("{}", render::source_sync(&report));
    Ok(())
}

fn cmd_thread_list(dir: &std::path::Path) -> Result<()> {
    let engine = open(dir)?;
    let threads = ops::open_threads(&engine).context("reading threads")?;
    println!("{}", render::thread_list(&threads));
    Ok(())
}

fn cmd_journal_add(dir: &std::path::Path, text: Option<&str>) -> Result<()> {
    use std::io::Read as _;

    let entry = match text {
        Some(t) => t.to_owned(),
        None => {
            let mut buf = String::new();
            std::io::stdin()
                .read_to_string(&mut buf)
                .context("reading the entry from stdin")?;
            buf
        }
    };
    let engine = open(dir)?;
    let id = ops::journal_add(&engine, &entry).context("recording the entry")?;
    // The id, never the entry. It is already in the vault; echoing it back
    // would put it in the terminal scrollback too (I8).
    println!("recorded {}", id.display_short());
    Ok(())
}

fn cmd_journal_import(dir: &std::path::Path, path: &std::path::Path) -> Result<()> {
    let engine = open(dir)?;
    let report = ops::journal_import(&engine, path).context("importing the journal")?;
    println!(
        "imported {} entry(ies), {} already present\n",
        report.ingested, report.skipped
    );
    Ok(())
}

fn cmd_egress_log(dir: &std::path::Path, days: Option<u32>) -> Result<()> {
    let engine = open(dir)?;
    let since = match days {
        Some(d) => ghostr_core::time::Timestamp::new(
            engine.now().utc_millis() - i64::from(d) * 86_400_000,
            0,
        ),
        None => ghostr_core::time::Timestamp::new(0, 0),
    };
    let records = ops::egress_log(&engine, since).context("reading the egress log")?;
    println!("{}", render::egress_log(&records));
    Ok(())
}

fn cmd_persona_show(dir: &std::path::Path) -> Result<()> {
    let engine = open(dir)?;
    match ops::persona_head(&engine).context("reading the persona")? {
        Some(model) => println!("{}", render::persona_show(&model)),
        None => println!(
            "no persona distilled yet\n  run `ghostr persona distill` once you have \
             {} memories or so",
            ghostr_persona::distill::MIN_CORPUS
        ),
    }
    Ok(())
}

fn cmd_persona_distill(dir: &std::path::Path, adopt: bool) -> Result<()> {
    let engine = open(dir)?;
    let candidate = ops::propose_persona(&engine).context("distilling")?;
    println!("{}", render::persona_candidate(&candidate));

    if adopt {
        ops::adopt_persona(&engine, &candidate).context("adopting")?;
        println!("adopted {}", candidate.model.version.display_short());
    }
    Ok(())
}

/// Adopting re-runs the distillation rather than reading a cached candidate.
///
/// Distillation is deterministic over the same corpus, so this reproduces what
/// `distill` printed — and if the corpus changed in between, adopting the
/// *current* model is the right answer rather than a stale one the user last
/// looked at.
fn cmd_persona_adopt(dir: &std::path::Path) -> Result<()> {
    let engine = open(dir)?;
    let candidate = ops::propose_persona(&engine).context("distilling")?;
    ops::adopt_persona(&engine, &candidate).context("adopting")?;
    println!("adopted {}", candidate.model.version.display_short());
    Ok(())
}

fn cmd_persona_diff(dir: &std::path::Path, from: u32, to: u32) -> Result<()> {
    let engine = open(dir)?;
    let diff = ops::persona_diff(&engine, from, to).context("diffing")?;
    println!("{}", render::persona_diff(&diff));
    Ok(())
}

fn cmd_persona_history(dir: &std::path::Path, limit: u32) -> Result<()> {
    let engine = open(dir)?;
    let versions = ops::persona_history(&engine, limit).context("reading history")?;
    println!("{}", render::persona_history(&versions));
    Ok(())
}
