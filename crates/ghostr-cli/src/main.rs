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

    /// Inspect sealed footage.
    #[command(subcommand)]
    Footage(FootageCommand),

    /// Submit the chain tip to OpenTimestamps. The only networked command.
    Anchor,

    /// Re-derive the chain from genesis and check every link.
    Verify,

    /// Show vault status.
    Status,
}

#[derive(Debug, Subcommand)]
enum SourceCommand {
    /// Add a source, after showing what adding it means.
    Add {
        /// Which adapter: `markdown`, `journal`, or `structlog`.
        kind: String,
        /// Path it reads from. Omitted for `journal`, which has none.
        #[arg(default_value = "")]
        path: String,
        /// For `structlog`, which schema its rows conform to:
        /// `places`, `people`, `habits`, `health`, or `media`.
        #[arg(long)]
        schema: Option<String>,
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
        Command::Init { import, tz } => cmd_init(&dir, import, &tz),
        Command::Ingest { path } => cmd_ingest(&dir, &path),
        Command::Memoria {
            date,
            dry_run,
            remote,
        } => cmd_memoria(&dir, &date, dry_run, remote),
        Command::Recap { date } => cmd_recap(&dir, &date),
        Command::Source(SourceCommand::Add { kind, path, schema }) => {
            cmd_source_add(&dir, &kind, &path, schema.as_deref())
        }
        Command::Source(SourceCommand::List) => cmd_source_list(&dir),
        Command::Source(SourceCommand::Sync { id }) => cmd_source_sync(&dir, id.as_deref()),
        Command::Thread(ThreadCommand::List) => cmd_thread_list(&dir),
        Command::Journal(JournalCommand::Add { text }) => cmd_journal_add(&dir, text.as_deref()),
        Command::Journal(JournalCommand::Import { path }) => cmd_journal_import(&dir, &path),
        Command::Egress(EgressCommand::Log { days }) => cmd_egress_log(&dir, days),
        Command::Footage(FootageCommand::List) => cmd_footage_list(&dir),
        Command::Footage(FootageCommand::Show { id }) => cmd_footage_show(&dir, id),
        Command::Anchor => cmd_anchor(&dir),
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

fn cmd_init(dir: &std::path::Path, import: bool, tz: &str) -> Result<()> {
    let home_tz = tz
        .parse()
        .map_err(|_| anyhow::anyhow!("`{tz}` is not an IANA timezone"))?;

    let imported = if import {
        let phrase = rpassword_prompt("mnemonic: ")?;
        Some(SecretString::new(phrase))
    } else {
        None
    };
    let pass = passphrase(true)?;

    let (engine, outcome) = Engine::init(
        dir,
        &pass,
        home_tz,
        imported,
        ghostr_crypto::kdf::Argon2Params::recommended(),
    )
    .context("creating the vault")?;

    println!("{}", render::init(&engine, &outcome, dir));
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

fn cmd_source_add(
    dir: &std::path::Path,
    kind: &str,
    path: &str,
    schema: Option<&str>,
) -> Result<()> {
    use ghostr_core::source::{LogSchema, SourceKindTag};
    use ghostr_engine::sources::{self, NewSource};

    let kind = match kind {
        "markdown" | "markdown_vault" => SourceKindTag::MarkdownVault,
        "journal" => SourceKindTag::Journal,
        "structlog" | "structured_log" => SourceKindTag::StructuredLog,
        other => bail!("unknown source kind `{other}` (try markdown, journal, or structlog)"),
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
    let report = ghostr_engine::sources::sync(&engine, only).context("syncing")?;
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
