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
    },

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
        Command::Memoria { date } => cmd_memoria(&dir, &date),
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

fn cmd_memoria(dir: &std::path::Path, date: &str) -> Result<()> {
    let engine = open(dir)?;
    let day = engine.resolve_date(date)?;
    let footage = ops::memoria(&engine, day).context("compiling footage")?;
    println!("{}", render::sealed(&footage));
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
