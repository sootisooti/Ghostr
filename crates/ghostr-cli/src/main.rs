//! `gst` — the Ghostr command-line interface.
//!
//! A thin shell over [`ghostr_engine`]. It holds no domain logic: it parses
//! arguments, calls the engine, and renders. `anyhow` is used here and only here
//! (with `xtask`), because a binary wants a chain of context and a library wants
//! a matchable enum.
//!
//! # The daily loop has to be fast
//!
//! `gst quest` is a ritual someone performs every morning. A loop that takes
//! ninety seconds gets done; one that takes five minutes does not, and a ghost
//! that stops being answered stops converging. Keystroke count is a product
//! requirement, not polish.
//!
//! # Status
//!
//! Scaffold. Command surface is defined; bodies are [`todo!`].

#![forbid(unsafe_code)]
// SCAFFOLD: every function body in this crate is `todo!()`. These allows exist
// only for the scaffold phase and are removed crate-by-crate as bodies land.
// `unused_variables` and `dead_code` fire because a diverging body never reads
// its arguments and never calls its helpers; parameters keep real names rather
// than `_` prefixes so the signatures stay readable. `clippy::todo` is denied
// workspace-wide by CLAUDE.md §5 and this is the documented exception.
// `cargo xtask scaffold-status` counts these markers so they cannot be quietly
// forgotten.
#![allow(unused_variables, dead_code, clippy::todo)]
// `print_stdout` is denied workspace-wide to keep memory content out of process
// output. This binary is the one place whose entire job is writing to stdout, so
// it is allowed here and rendering stays confined to `render`.
#![allow(clippy::print_stdout, clippy::print_stderr)]

mod render;

use clap::{Parser, Subcommand};

/// A digital ghost: an agent that clones your identity, verified daily.
#[derive(Debug, Parser)]
#[command(name = "gst", version, about, long_about = None)]
struct Cli {
    /// Path to the config file.
    #[arg(long, global = true)]
    config: Option<std::path::PathBuf>,

    /// Machine-readable output.
    #[arg(long, global = true)]
    json: bool,

    #[command(subcommand)]
    command: Command,
}

/// What to do.
#[derive(Debug, Subcommand)]
enum Command {
    /// Create a keystore and a chain, or import an existing seed.
    ///
    /// Prints the plain-language warning that a leaked seed is unrecoverable —
    /// at the moment it is generated, not in a footnote (THREAT_MODEL §T5).
    Init {
        /// Import an existing BIP-39 mnemonic instead of generating one.
        #[arg(long)]
        import: bool,
        /// Words to generate.
        #[arg(long, default_value = "12")]
        words: u8,
    },

    /// Unlock the keystore for this session.
    Unlock,

    /// Lock the keystore now.
    Lock,

    /// Engine, chain, and model status.
    Status,

    /// Record a journal entry.
    ///
    /// The shortest path from a thought to the corpus. Everything else can be
    /// slow; this cannot.
    Note {
        /// The text. Reads stdin when absent.
        text: Option<String>,
        /// Mark as never egressing to a remote model.
        #[arg(long)]
        secret: bool,
    },

    /// Manage data sources.
    #[command(subcommand)]
    Source(SourceCommand),

    /// Compile and seal any pending windows, then anchor.
    Seal {
        /// Compile and validate without sealing.
        #[arg(long)]
        dry_run: bool,
    },

    /// Show a day's footage.
    Recap {
        /// Which day: `YYYY-MM-DD`, `today`, `yesterday`, or a `seq:N`.
        ///
        /// Parsed in the handler rather than by clap so relative words work, and
        /// so an out-of-range date fails with a message about the chain rather
        /// than about argument syntax.
        date: Option<String>,
    },

    /// List open threads.
    Threads {
        /// Include stalled threads.
        #[arg(long)]
        all: bool,
    },

    /// Answer today's quests.
    Quest {
        /// Answer at most this many.
        #[arg(long)]
        limit: Option<u8>,
    },

    /// Show the fidelity score.
    Fidelity {
        /// Break down by facet.
        #[arg(long)]
        by_facet: bool,
        /// Which window.
        #[arg(long, default_value = "rolling90")]
        window: String,
    },

    /// Inspect the persona model.
    #[command(subcommand)]
    Persona(PersonaCommand),

    /// Ask the ghost something.
    Ask {
        /// The question.
        question: String,
    },

    /// Verify the chain and its anchors.
    ///
    /// Reports each check separately, and says when a check was skipped rather
    /// than passed (ARCHITECTURE §4.5).
    Verify {
        /// Start sequence, or genesis.
        #[arg(long)]
        from: Option<String>,
    },

    /// Read the egress log: everything that left this device.
    #[command(name = "egress")]
    Egress {
        /// How many days back.
        #[arg(long, default_value = "30")]
        days: u32,
    },

    /// Crypto-shred a memory or every memory naming a person.
    ///
    /// Irreversible, and re-prompts for the passphrase first.
    Forget {
        /// A memory id, or `person:<name>`.
        target: String,
    },

    /// Export a verifiable bundle for a third party.
    Export {
        /// Where to write it.
        #[arg(long)]
        out: std::path::PathBuf,
        /// Include held-out quests so a verifier can recompute the score.
        #[arg(long)]
        reveal_holdout: bool,
    },
}

/// Source management.
#[derive(Debug, Subcommand)]
enum SourceCommand {
    /// Add a source.
    Add {
        /// A path or URL.
        target: String,
        /// Force a source kind rather than inferring it.
        #[arg(long)]
        kind: Option<String>,
    },
    /// List configured sources.
    List,
    /// Pull from one source, or all of them.
    Sync {
        /// Which source.
        id: Option<String>,
    },
    /// Disable a source without deleting what it produced.
    Disable {
        /// Which source.
        id: String,
    },
}

/// Persona inspection.
#[derive(Debug, Subcommand)]
enum PersonaCommand {
    /// Show the current model.
    Show {
        /// Only this facet.
        #[arg(long)]
        facet: Option<String>,
    },
    /// Diff two versions.
    Diff {
        /// From version ordinal.
        from: u32,
        /// To version ordinal. Defaults to head.
        to: Option<u32>,
    },
    /// List versions.
    History {
        /// How many.
        #[arg(long, default_value = "20")]
        limit: u32,
    },
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    run(cli)
}

/// Dispatches a parsed command.
///
/// # Errors
///
/// Returns an error if the engine fails. `main` renders it with its context
/// chain and exits non-zero.
fn run(cli: Cli) -> anyhow::Result<()> {
    todo!("build the engine from config and dispatch the subcommand")
}
